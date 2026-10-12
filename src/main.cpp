// ESP32 AdBlock — DNS sinkhole + web dashboard (no external PSRAM).
//
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// A Bloom filter in RAM lets definite misses skip flash; hit rate is workload-dependent.
// Async upstream forwarding handles multiple concurrent queries.
// TCP DNS client listener (the current upstream forwarder is UDP).
// Dashboard at http://c3adblock.local with Basic Auth + CSRF token.
//
// Improvements over the original:
//  - Event-loop serviced UDP forwarding for concurrent queries
//  - Bloom filter pre-filter in RAM
//  - AAAA sinkhole (blocked IPv6 queries answered with ::, not leaked)
//  - TCP DNS on port 53
//  - Dashboard auth (Basic Auth + CSRF token)
//  - Client table with LRU eviction
//  - Decoupled ban storage (independent of client table)
//  - Idle-gated remote blocklist fetch (reduces, but does not eliminate, DNS stalls)
//  - HTTPS remote fetch path does not disable TLS verification
//  - millis() wraparound-safe timing
//  - Blocklist v2 CRC validation with v1 read compatibility
//  - MSB-prefix index for flash hash lookup
//  - Authenticated dashboard, CSRF-protected mutations and password-protected OTA
//  - captive portal for first-boot WiFi config
//  - Optional DHCP server (hands out C3 as DNS for plug-and-play)
//  - ETag/Cache-Control for dashboard HTML
//  - Logging macros (silence with -DNDEBUG)
//  - Custom domains sorted + binary-searched
//  - 1232-byte DNS buffer (handles EDNS-sized responses)
//  - parseQuery with robust bounds checking
//  - No delay(1) in loop (removed throughput cap)
//  - Dead Dev.label field removed

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <WiFiServer.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ArduinoOTA.h>
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "secrets.h"
#include "dashboard_html.h"
#include "dns_packet.h"

// ---- config ----
static const IPAddress UPSTREAM(9, 9, 9, 9);
static const uint16_t DNS_PORT = 53;
static const uint16_t DHCP_PORT = 67;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const char* BLOCKLIST_BACKUP_PATH = "/blocklist.bak";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const int DNS_BUF_SIZE = 1232;       // RFC 6891 max UDP DNS payload
static const int MAX_PENDING = 32;          // concurrent outstanding upstream queries
static const int MAX_CLIENTS = 96;
static const int MAX_CUSTOM = 200;
static const int MAX_BAN = 32;
static const int MAX_DHCP_LEASES = 32;
static const int MAX_REWRITES = 32;
static const int DNS_CACHE_SIZE = 16;
static const uint32_t UPSTREAM_TIMEOUT_MS = 2000;
static const uint32_t DNS_CACHE_TTL_MS = 30000;
static const uint32_t REMOTE_FETCH_IDLE_MS = 3000;  // only fetch when DNS idle this long
static const char* DASHBOARD_ETAG = "c3adb-v3";

// ---- logging ----
#ifdef NDEBUG
#define LOG(...) ((void)0)
#define LOGN(...) ((void)0)
#else
#define LOG(...) Serial.printf(__VA_ARGS__)
#define LOGN(...) Serial.println(__VA_ARGS__)
#endif

static void recoverConfigFile(const char* active, const char* staged, const char* backup) {
  if (!LittleFS.exists(active) && LittleFS.exists(backup))
    LittleFS.rename(backup, active);
  else if (LittleFS.exists(active))
    LittleFS.remove(backup);
  LittleFS.remove(staged);
}

static bool replaceStagedFile(const char* active, const char* staged, const char* backup) {
  LittleFS.remove(backup);
  bool hadActive = LittleFS.exists(active);
  if (hadActive && !LittleFS.rename(active, backup)) return false;
  if (!LittleFS.rename(staged, active)) {
    if (hadActive) LittleFS.rename(backup, active);
    return false;
  }
  if (hadActive) LittleFS.remove(backup);
  return true;
}

// ---- forward declarations ----
WebServer web(80);
static const char* COLLECTED_HEADERS[] = {"Authorization", "If-None-Match", "Origin", "Referer", "X-CSRF-Token"};
String updateUrl, updateStatus = "never";
String captiveToken;
static bool blocklistValid = false;
static bool blocklistReadError = false;
uint32_t updateIntervalH = 24, lastCheckMs = 0;
static uint32_t lastDnsActivityMs = 0;
bool dhcpEnabled = false;
bool paused = false;
static bool authPasswordGenerated = false;
static bool saveDhcpCfg();
static bool savePausedCfg();
static bool saveWifiCfg(const String& ssid, const String& pass);
static bool saveAuthCfg();
static bool fetchBlocklist(String url);

// ---- hashing ----------
static uint64_t fnv64(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h;
}
static inline uint64_t fnv40(const char* s, size_t n) { return fnv64(s, n) & HASH_MASK; }

// ---- blocklist (flash hash table + RAM bloom filter) ----
static const uint8_t BL_MAGIC[4] = {'C','A','D','B'};
static const uint8_t BL_VERSION = 2;
static const int BL_HEADER_SIZE = 20;

File blocklist;
uint32_t numHashes = 0;
uint32_t hashTableOffset = 0;       // offset in file where sorted hashes begin
uint32_t prefixIndex[257];

uint8_t* bloomFilter = nullptr;     // malloc'd RAM bloom filter
uint32_t bloomBits = 0;
uint8_t bloomK = 0;

static bool bloomMayContain(uint64_t h64) {
  if (!bloomFilter || bloomBits == 0 || bloomK == 0) return true; // fail open -> check flash
  uint32_t h1 = (uint32_t)(h64 & 0xFFFFFFFF);
  uint32_t h2 = (uint32_t)(h64 >> 32);
  if (h2 == 0) h2 = 0xFFFFFFFF;
  for (uint8_t i = 0; i < bloomK; i++) {
    uint32_t pos = (h1 + i * h2) % bloomBits;
    if (!(bloomFilter[pos >> 3] & (1 << (pos & 7)))) return false;
  }
  return true;
}

static bool inFlash(uint64_t h) {
  if (!blocklist || numHashes == 0) return false;
  uint8_t prefix = (uint8_t)(h >> 32);
  int32_t lo = (int32_t)prefixIndex[prefix];
  int32_t hi = (int32_t)prefixIndex[prefix + 1] - 1;
  uint8_t b[HASH_BYTES];
  while (lo <= hi) {
    int32_t mid = (lo + hi) >> 1;
    if (!blocklist.seek(hashTableOffset + (uint32_t)mid * HASH_BYTES) ||
        blocklist.read(b, HASH_BYTES) != HASH_BYTES) {
      blocklistReadError = true;
      LOGN("[bl] flash lookup read failed; treating candidate as blocked");
      return true;
    }
    uint64_t v = 0;
    for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
    if (v < h) lo = mid + 1;
    else if (v > h) hi = mid - 1;
    else return true;
  }
  return false;
}

// ---- custom domains (sorted for binary search) ----
String customDom[MAX_CUSTOM];
uint64_t customHash[MAX_CUSTOM];  // kept sorted
int numCustom = 0;

struct Rewrite { String domain; IPAddress address; };
struct DecisionCacheEntry {
  char domain[254];
  uint32_t checkedAt;
  bool blocked;
  bool valid;
};
Rewrite rewrites[MAX_REWRITES];
int numRewrites = 0;
static DecisionCacheEntry decisionCache[DNS_CACHE_SIZE];
static uint8_t nextCacheEntry = 0;

static void clearDecisionCache() {
  memset(decisionCache, 0, sizeof(decisionCache));
  nextCacheEntry = 0;
}

static void sortCustom() {
  for (int i = 1; i < numCustom; i++) {
    uint64_t h = customHash[i]; String d = customDom[i];
    int j = i - 1;
    while (j >= 0 && customHash[j] > h) { customHash[j+1] = customHash[j]; customDom[j+1] = customDom[j]; j--; }
    customHash[j+1] = h; customDom[j+1] = d;
  }
}
static bool inCustom(uint64_t h) {
  int lo = 0, hi = numCustom - 1;
  while (lo <= hi) {
    int mid = (lo + hi) >> 1;
    if (customHash[mid] < h) lo = mid + 1;
    else if (customHash[mid] > h) hi = mid - 1;
    else return true;
  }
  return false;
}

// ---- isBlocked: check domain + parent suffixes, bloom-pre-filtered ----
// Walks parent suffixes: ads.x.example -> x.example -> example.
// Stops before the bare TLD (a block on "com" would break everything).
static bool isBlocked(const char* domain, size_t dlen) {
  if (paused || !domain || dlen == 0 || dlen >= sizeof(decisionCache[0].domain)) return false;
  uint32_t now = millis();
  for (int i = 0; i < DNS_CACHE_SIZE; i++) {
    DecisionCacheEntry& entry = decisionCache[i];
    if (entry.valid && (now - entry.checkedAt) < DNS_CACHE_TTL_MS &&
        strlen(entry.domain) == dlen && memcmp(entry.domain, domain, dlen) == 0)
      return entry.blocked;
  }
  const char* p = domain;
  size_t remaining = dlen;
  bool blocked = false;
  while (remaining > 0) {
    uint64_t h64 = fnv64(p, remaining);
    uint64_t h40 = h64 & HASH_MASK;
    bool checkFlash = bloomMayContain(h64);  // false = definitely not in list, skip flash
    if ((checkFlash && inFlash(h40)) || inCustom(h40)) { blocked = true; break; }
    const char* dot = (const char*)memchr(p, '.', remaining);
    if (!dot) break;
    size_t consumed = (size_t)(dot - p) + 1;
    remaining -= consumed;
    p = dot + 1;
    if (!memchr(p, '.', remaining)) break;  // don't test bare TLD
  }
  DecisionCacheEntry& entry = decisionCache[nextCacheEntry++ % DNS_CACHE_SIZE];
  memcpy(entry.domain, domain, dlen);
  entry.domain[dlen] = 0;
  entry.checkedAt = now;
  entry.blocked = blocked;
  entry.valid = true;
  return blocked;
}

// ---- persistence: custom domains ----
static bool validDomain(const String& d) {
  if (!d.length() || d.length() > 253 || d.indexOf('.') < 0 ||
      d[0] == '.' || d[d.length() - 1] == '.') return false;
  int labelLength = 0;
  for (size_t i = 0; i < d.length(); i++) {
    char ch = d[i];
    if (ch == '.') {
      if (labelLength == 0 || labelLength > 63 || d[i - 1] == '-') return false;
      labelLength = 0;
    } else {
      if (!(isalnum((unsigned char)ch) || ch == '-') ||
          (labelLength == 0 && ch == '-')) return false;
      labelLength++;
    }
  }
  return labelLength > 0 && labelLength <= 63 && d[d.length() - 1] != '-';
}

static void loadRewrites() {
  numRewrites = 0;
  File f = LittleFS.open("/rewrites.txt", "r");
  if (!f) return;
  while (f.available() && numRewrites < MAX_REWRITES) {
    String line = f.readStringUntil('\n');
    line.trim();
    int separator = line.indexOf(' ');
    if (separator < 1) continue;
    String domain = line.substring(0, separator);
    String ipText = line.substring(separator + 1);
    domain.toLowerCase();
    IPAddress address;
    if (validDomain(domain) && address.fromString(ipText))
      rewrites[numRewrites++] = {domain, address};
  }
  f.close();
}

static bool saveRewrites() {
  File f = LittleFS.open("/rewrites.new", "w");
  if (!f) return false;
  for (int i = 0; i < numRewrites; i++)
    f.println(rewrites[i].domain + " " + rewrites[i].address.toString());
  bool ok = f.getWriteError() == 0;
  f.close();
  if (!ok) { LittleFS.remove("/rewrites.new"); return false; }
  return replaceStagedFile("/rewrites.txt", "/rewrites.new", "/rewrites.bak");
}

static bool addRewrite(String domain, String ipText) {
  domain.trim();
  domain.toLowerCase();
  if (domain.startsWith("www.")) domain = domain.substring(4);
  IPAddress address;
  if (!validDomain(domain) || !address.fromString(ipText)) return false;
  for (int i = 0; i < numRewrites; i++) {
    if (rewrites[i].domain == domain) {
      IPAddress previous = rewrites[i].address;
      rewrites[i].address = address;
      if (!saveRewrites()) { rewrites[i].address = previous; return false; }
      clearDecisionCache();
      return true;
    }
  }
  if (numRewrites >= MAX_REWRITES) return false;
  rewrites[numRewrites++] = {domain, address};
  if (!saveRewrites()) { numRewrites--; return false; }
  clearDecisionCache();
  return true;
}

static bool removeRewrite(String domain) {
  domain.trim();
  domain.toLowerCase();
  if (domain.startsWith("www.")) domain = domain.substring(4);
  for (int i = 0; i < numRewrites; i++) {
    if (rewrites[i].domain == domain) {
      Rewrite removed = rewrites[i];
      for (int j = i; j < numRewrites - 1; j++) rewrites[j] = rewrites[j + 1];
      numRewrites--;
      if (!saveRewrites()) {
        for (int j = numRewrites; j > i; j--) rewrites[j] = rewrites[j - 1];
        rewrites[i] = removed;
        numRewrites++;
        return false;
      }
      clearDecisionCache();
      return true;
    }
  }
  return false;
}

static bool findRewrite(const char* domain, size_t length, IPAddress& address) {
  for (int i = 0; i < numRewrites; i++) {
    if (rewrites[i].domain.length() == length &&
        memcmp(rewrites[i].domain.c_str(), domain, length) == 0) {
      address = rewrites[i].address;
      return true;
    }
  }
  return false;
}

static void loadCustom() {
  numCustom = 0;
  File f = LittleFS.open("/custom.txt", "r");
  if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (validDomain(l)) {
      customDom[numCustom] = l;
      customHash[numCustom] = fnv40(l.c_str(), l.length());
      numCustom++;
    }
  }
  f.close();
  sortCustom();
  clearDecisionCache();
}
static bool saveCustom() {
  File f = LittleFS.open("/custom.new", "w");
  if (!f) return false;
  for (int i = 0; i < numCustom; i++) f.println(customDom[i]);
  bool ok = f.getWriteError() == 0;
  f.close();
  if (!ok) { LittleFS.remove("/custom.new"); return false; }
  return replaceStagedFile("/custom.txt", "/custom.new", "/custom.bak");
}
static bool addCustom(String d) {
  d.trim(); d.toLowerCase();
  if (d.startsWith("www.")) d = d.substring(4);
  if (!validDomain(d) || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d;
  customHash[numCustom] = fnv40(d.c_str(), d.length());
  numCustom++;
  sortCustom();
  if (!saveCustom()) {
    for (int i = 0; i < numCustom; i++) {
      if (customDom[i] == d) {
        for (int j = i; j < numCustom - 1; j++) {
          customDom[j] = customDom[j + 1];
          customHash[j] = customHash[j + 1];
        }
        numCustom--;
        break;
      }
    }
    return false;
  }
  clearDecisionCache();
  return true;
}
static bool removeCustom(String d) {
  d.toLowerCase();
  if (d.startsWith("www.")) d = d.substring(4);
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    String removedDomain = customDom[i];
    uint64_t removedHash = customHash[i];
    for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; }
    numCustom--;
    if (!saveCustom()) {
      for (int j = numCustom; j > i; j--) {
        customDom[j] = customDom[j - 1];
        customHash[j] = customHash[j - 1];
      }
      customDom[i] = removedDomain;
      customHash[i] = removedHash;
      numCustom++;
      return false;
    }
    clearDecisionCache();
    return true;
  }
  return false;
}

// ---- banned IPs (decoupled from client table) ----
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static bool addBannedIP(uint32_t ip) {
  if (isBannedIP(ip)) return false;
  if (numBanned >= MAX_BAN) return false;
  bannedIP[numBanned++] = ip;
  return true;
}
static bool removeBannedIP(uint32_t ip) {
  for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) {
    for (int j = i; j < numBanned - 1; j++) bannedIP[j] = bannedIP[j+1];
    numBanned--;
    return true;
  }
  return false;
}
static void loadBanned() {
  numBanned = 0;
  File f = LittleFS.open("/banned.txt", "r");
  if (!f) return;
  while (f.available() && numBanned < MAX_BAN) {
    String l = f.readStringUntil('\n'); l.trim();
    IPAddress ip;
    if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip;
  }
  f.close();
}
static bool saveBanned() {
  File f = LittleFS.open("/banned.new", "w");
  if (!f) return false;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  bool ok = f.getWriteError() == 0;
  f.close();
  if (!ok) { LittleFS.remove("/banned.new"); return false; }
  return replaceStagedFile("/banned.txt", "/banned.new", "/banned.bak");
}

// ---- client table (with LRU eviction) ----
struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; };
Dev clients[MAX_CLIENTS]; int numClients = 0;
uint32_t totalBlocked = 0, totalAllowed = 0;

static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6);
  ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++)
    if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  int slot = numClients;
  if (numClients >= MAX_CLIENTS) {
    // Evict stalest client
    int oldest = 0;
    for (int i = 1; i < numClients; i++)
      if (clients[i].lastSeen < clients[oldest].lastSeen) oldest = i;
    slot = oldest;
  } else {
    numClients++;
  }
  Dev* c = &clients[slot];
  c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis();
  c->banned = isBannedIP(ip);
  getMac(ip, c->mac);
  return c;
}

// ---- DNS blocking (A -> 0.0.0.0, AAAA -> ::) ----
static int appendResponseOpt(uint8_t* pkt, int length, bool hasEdns,
                             uint16_t udpPayload, uint16_t ednsFlags) {
  if (!hasEdns) return length;
  if (length + 11 > DNS_BUF_SIZE) return 0;
  const uint8_t opt[] = {0, 0,41, 0,0, 0,0,0,0, 0,0};
  memcpy(pkt + length, opt, sizeof(opt));
  pkt[length + 3] = (uint8_t)(udpPayload >> 8);
  pkt[length + 4] = (uint8_t)udpPayload;
  pkt[length + 7] = (uint8_t)(ednsFlags >> 8);
  pkt[length + 8] = (uint8_t)ednsFlags;
  pkt[10] = 0;
  pkt[11] = 1;
  return length + sizeof(opt);
}

static int buildBlocked(uint8_t* pkt, int qend, uint16_t qtype,
                        bool hasEdns, uint16_t udpPayload, uint16_t ednsFlags) {
  if (qend < 17 || qend + 28 > DNS_BUF_SIZE) return 0;
  uint8_t rd = pkt[2] & 0x01;
  uint8_t cd = pkt[3] & 0x10;
  pkt[2] = 0x80 | rd;
  pkt[3] = 0x80 | cd | ((qtype == 1 || qtype == 28) ? 0 : 3);
  pkt[6] = 0; pkt[7] = (qtype == 1 || qtype == 28) ? 1 : 0;
  pkt[8] = 0; pkt[9] = 0; pkt[10] = 0; pkt[11] = 0;
  if (qtype == 1) {
    // A record: 0.0.0.0, TTL 300
    const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
    memcpy(pkt + qend, ans, sizeof(ans));
    return appendResponseOpt(pkt, qend + sizeof(ans), hasEdns, udpPayload, ednsFlags);
  }
  if (qtype == 28) {
    // AAAA record: ::, TTL 300
    const uint8_t ans[] = {0xC0,0x0C, 0,28, 0,1, 0,0,1,0x2C, 0,16, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    memcpy(pkt + qend, ans, sizeof(ans));
    return appendResponseOpt(pkt, qend + sizeof(ans), hasEdns, udpPayload, ednsFlags);
  }
  return appendResponseOpt(pkt, qend, hasEdns, udpPayload, ednsFlags);
}

static int buildRewriteA(uint8_t* pkt, int qend, const IPAddress& address,
                         bool hasEdns, uint16_t udpPayload, uint16_t ednsFlags) {
  if (qend < 17 || qend + 16 > DNS_BUF_SIZE) return 0;
  uint8_t rd = pkt[2] & 0x01;
  uint8_t cd = pkt[3] & 0x10;
  pkt[2] = 0x80 | rd; pkt[3] = 0x80 | cd;
  pkt[6] = 0; pkt[7] = 1;
  pkt[8] = pkt[9] = pkt[10] = pkt[11] = 0;
  const uint8_t record[] = {0xC0,0x0C, 0,1, 0,1, 0,0,0,60, 0,4};
  memcpy(pkt + qend, record, sizeof(record));
  for (int i = 0; i < 4; i++) pkt[qend + sizeof(record) + i] = address[i];
  return appendResponseOpt(pkt, qend + sizeof(record) + 4, hasEdns, udpPayload, ednsFlags);
}

// ---- async DNS forwarding ----
WiFiUDP dnsServer;     // listens on :53 for client queries
WiFiUDP upstream;      // ephemeral port for upstream queries/replies
WiFiUDP tcpUpstream;   // separate UDP socket used while servicing client TCP DNS

struct Pending {
  uint32_t clientIP;
  uint16_t clientPort;
  uint16_t originalID;
  uint16_t wireID;
  uint32_t sentMs;
  uint16_t questionLen;
  uint8_t queryFlags2;
  uint8_t queryFlags3;
  uint8_t question[260];
  bool active;
};
Pending pending[MAX_PENDING];
int pendingCount = 0;

static int buildServfail(uint8_t* pkt, int qend) {
  if (qend < 17 || qend > DNS_BUF_SIZE) return 0;
  uint8_t rd = pkt[2] & 0x01;
  uint8_t cd = pkt[3] & 0x10;
  pkt[2] = 0x80 | rd;
  pkt[3] = 0x80 | cd | 2;
  pkt[4] = 0; pkt[5] = 1;
  pkt[6] = pkt[7] = pkt[8] = pkt[9] = pkt[10] = pkt[11] = 0;
  return qend;
}

static void sendPendingServfail(const Pending& item) {
  uint8_t response[12 + sizeof(item.question)];
  memset(response, 0, 12);
  response[0] = (uint8_t)(item.originalID >> 8);
  response[1] = (uint8_t)item.originalID;
  response[2] = 0x80 | (item.queryFlags2 & 0x01);
  response[3] = 0x80 | (item.queryFlags3 & 0x10) | 2;
  response[5] = 1;
  memcpy(response + 12, item.question, item.questionLen);
  dnsServer.beginPacket(item.clientIP, item.clientPort);
  dnsServer.write(response, 12 + item.questionLen);
  dnsServer.endPacket();
}

static int findPendingByWireID(uint16_t wireID) {
  for (int i = 0; i < MAX_PENDING; i++)
    if (pending[i].active && pending[i].wireID == wireID) return i;
  return -1;
}

static int findFreeSlot() {
  for (int i = 0; i < MAX_PENDING; i++) if (!pending[i].active) return i;
  return -1;
}
static void expirePending() {
  uint32_t now = millis();
  for (int i = 0; i < MAX_PENDING; i++)
    if (pending[i].active && (now - pending[i].sentMs) > UPSTREAM_TIMEOUT_MS) {
      sendPendingServfail(pending[i]);
      pending[i].active = false;
      pendingCount--;
    }
}
static void pollUpstream(uint8_t* buf, int bufSize) {
  int sz = upstream.parsePacket();
  if (sz <= 0) return;
  if (sz > bufSize) {
    uint8_t discard[DNS_BUF_SIZE];
    while (sz > 0) {
      int amount = sz > (int)sizeof(discard) ? sizeof(discard) : sz;
      upstream.read(discard, amount);
      sz -= amount;
    }
    return;
  }
  if (upstream.remoteIP() != UPSTREAM || upstream.remotePort() != 53) {
    uint8_t discard[DNS_BUF_SIZE];
    while (sz > 0) {
      int amount = sz > (int)sizeof(discard) ? sizeof(discard) : sz;
      upstream.read(discard, amount);
      sz -= amount;
    }
    return;
  }
  int rlen = upstream.read(buf, bufSize);
  if (rlen < 12 || !(buf[2] & 0x80)) return;
  uint16_t replyID = (buf[0] << 8) | buf[1];
  int slot = findPendingByWireID(replyID);
  if (slot < 0) return;
  if (buf[4] != 0 || buf[5] != 1 ||
      rlen < 12 + pending[slot].questionLen ||
      memcmp(buf + 12, pending[slot].question, pending[slot].questionLen) != 0)
    return;
  // Restore original query ID
  buf[0] = (pending[slot].originalID >> 8) & 0xFF;
  buf[1] = pending[slot].originalID & 0xFF;
  dnsServer.beginPacket(pending[slot].clientIP, pending[slot].clientPort);
  dnsServer.write(buf, rlen);
  dnsServer.endPacket();
  totalAllowed++;
  Dev* c = getClient(pending[slot].clientIP);
  if (c) c->allowed++;
  pending[slot].active = false;
  pendingCount--;
}

static uint8_t dnsBuf[DNS_BUF_SIZE];

static void handleDns() {
  int sz = dnsServer.parsePacket();
  if (sz <= 0) return;
  if (sz > DNS_BUF_SIZE) { dnsServer.read(dnsBuf, sizeof(dnsBuf)); return; }
  lastDnsActivityMs = millis();
  IPAddress cip = dnsServer.remoteIP();
  uint16_t cport = dnsServer.remotePort();
  int qlen = dnsServer.read(dnsBuf, sizeof(dnsBuf));
  if (qlen < 13) return;

  char domain[256]; uint16_t qtype = 0; int qend = qlen;
  bool hasEdns; uint16_t udpPayload, ednsFlags;
  size_t dl = parseDnsQuery(dnsBuf, qlen, domain, &qtype, &qend, &hasEdns,
                            &udpPayload, &ednsFlags, DNS_BUF_SIZE);
  if (!dl) return;

  Dev* c = getClient((uint32_t)cip);
  bool ban = c && c->banned;
  IPAddress rewriteAddress;
  bool rewritten = !ban && qtype == 1 && findRewrite(domain, dl, rewriteAddress);
  bool blocked = !paused && (ban || (!rewritten && (numHashes || numCustom) && isBlocked(domain, dl)));

  if (rewritten) {
    int rlen = buildRewriteA(dnsBuf, qend, rewriteAddress, hasEdns, udpPayload, ednsFlags);
    if (!rlen) return;
    dnsServer.beginPacket(cip, cport);
    dnsServer.write(dnsBuf, rlen);
    dnsServer.endPacket();
    totalAllowed++;
    if (c) c->allowed++;
  } else if (blocked) {
    int rlen = buildBlocked(dnsBuf, qend, qtype, hasEdns, udpPayload, ednsFlags);
    if (!rlen) return;
    totalBlocked++;
    if (c) c->blocked++;
    dnsServer.beginPacket(cip, cport);
    dnsServer.write(dnsBuf, rlen);
    dnsServer.endPacket();
  } else {
    int slot = findFreeSlot();
    if (slot < 0) {
      int rlen = buildServfail(dnsBuf, qend);
      if (rlen) {
        dnsServer.beginPacket(cip, cport);
        dnsServer.write(dnsBuf, rlen);
        dnsServer.endPacket();
      }
      return;
    }
    if (hasEdns) {
      dnsBuf[qend + 3] = (uint8_t)(udpPayload >> 8);
      dnsBuf[qend + 4] = (uint8_t)udpPayload;
    }
    uint16_t origID = (dnsBuf[0] << 8) | dnsBuf[1];
    uint16_t wireID = (uint16_t)esp_random();
    while (findPendingByWireID(wireID) >= 0) wireID++;
    dnsBuf[0] = (wireID >> 8) & 0xFF;
    dnsBuf[1] = wireID & 0xFF;
    pending[slot].clientIP = (uint32_t)cip;
    pending[slot].clientPort = cport;
    pending[slot].originalID = origID;
    pending[slot].wireID = wireID;
    pending[slot].sentMs = millis();
    pending[slot].questionLen = (uint16_t)(qend - 12);
    pending[slot].queryFlags2 = dnsBuf[2];
    pending[slot].queryFlags3 = dnsBuf[3];
    memcpy(pending[slot].question, dnsBuf + 12, qend - 12);
    pending[slot].active = true;
    pendingCount++;
    bool started = upstream.beginPacket(UPSTREAM, 53) == 1;
    size_t written = started ? upstream.write(dnsBuf, qlen) : 0;
    bool ended = started && upstream.endPacket() == 1;
    bool sent = started && written == (size_t)qlen && ended;
    if (!sent) {
      sendPendingServfail(pending[slot]);
      pending[slot].active = false;
      pendingCount--;
      return;
    }
  }
}

// ---- TCP DNS (one query per connection) ----
WiFiServer tcpDnsServer(DNS_PORT);
WiFiClient tcpDnsClient;
static uint8_t tcpBuf[DNS_BUF_SIZE];

static int forwardUpstreamSync(uint8_t* pkt, int qlen) {
  uint16_t origID = (pkt[0] << 8) | pkt[1];
  uint16_t wireID = (uint16_t)esp_random();
  pkt[0] = (wireID >> 8) & 0xFF; pkt[1] = wireID & 0xFF;
  bool started = tcpUpstream.beginPacket(UPSTREAM, 53) == 1;
  size_t written = started ? tcpUpstream.write(pkt, qlen) : 0;
  bool ended = started && tcpUpstream.endPacket() == 1;
  bool sent = started && written == (size_t)qlen && ended;
  pkt[0] = (origID >> 8) & 0xFF; pkt[1] = origID & 0xFF;  // restore for blocked path
  if (!sent) return 0;
  uint32_t t0 = millis();
  while (millis() - t0 < UPSTREAM_TIMEOUT_MS) {
    int sz = tcpUpstream.parsePacket();
    if (sz > 0) {
      if (tcpUpstream.remoteIP() != UPSTREAM || tcpUpstream.remotePort() != 53) {
        uint8_t discard[DNS_BUF_SIZE];
        while (sz > 0) {
          int amount = sz > (int)sizeof(discard) ? sizeof(discard) : sz;
          tcpUpstream.read(discard, amount);
          sz -= amount;
        }
        continue;
      }
      int n = tcpUpstream.read(pkt, DNS_BUF_SIZE);
      if (n >= 12 && (((uint16_t)pkt[0] << 8) | pkt[1]) == wireID && (pkt[2] & 0x80)) {
        pkt[0] = (origID >> 8) & 0xFF; pkt[1] = origID & 0xFF;
        return n;
      }
      return 0;
    }
    delay(1);
  }
  return 0;
}

static void handleTcpDns() {
  if (!tcpDnsClient || !tcpDnsClient.connected()) {
    tcpDnsClient = tcpDnsServer.accept();
    if (!tcpDnsClient) return;
  }
  if (!tcpDnsClient.connected()) return;
  if (tcpDnsClient.available() < 2) return;

  uint8_t lenBuf[2];
  tcpDnsClient.read(lenBuf, 2);
  uint16_t msgLen = (lenBuf[0] << 8) | lenBuf[1];
  if (msgLen > DNS_BUF_SIZE) { tcpDnsClient.stop(); return; }

  int total = 0;
  uint32_t t0 = millis();
  while (total < msgLen && tcpDnsClient.connected()) {
    if (tcpDnsClient.available()) {
      int n = tcpDnsClient.read(tcpBuf + total, msgLen - total);
      if (n <= 0) break;
      total += n;
    } else {
      if (millis() - t0 > UPSTREAM_TIMEOUT_MS) break;
      delay(1);
    }
  }
  if (total < msgLen) { tcpDnsClient.stop(); return; }
  IPAddress clientIP = tcpDnsClient.remoteIP();

  char domain[256]; uint16_t qtype = 0; int qend = total;
  bool hasEdns; uint16_t udpPayload, ednsFlags;
  size_t dl = parseDnsQuery(tcpBuf, total, domain, &qtype, &qend, &hasEdns,
                            &udpPayload, &ednsFlags, DNS_BUF_SIZE);
  if (!dl) { tcpDnsClient.stop(); return; }
  Dev* c = getClient((uint32_t)clientIP);
  bool ban = c && c->banned;
  IPAddress rewriteAddress;
  bool rewritten = !ban && qtype == 1 && findRewrite(domain, dl, rewriteAddress);
  bool blocked = !paused && (ban || (!rewritten && (numHashes || numCustom) && isBlocked(domain, dl)));

  int rlen;
  if (rewritten) {
    rlen = buildRewriteA(tcpBuf, qend, rewriteAddress, hasEdns, udpPayload, ednsFlags);
    totalAllowed++; if (c) c->allowed++;
  } else if (blocked) {
    rlen = buildBlocked(tcpBuf, qend, qtype, hasEdns, udpPayload, ednsFlags);
    totalBlocked++; if (c) c->blocked++;
  } else {
    if (hasEdns) {
      tcpBuf[qend + 3] = (uint8_t)(udpPayload >> 8);
      tcpBuf[qend + 4] = (uint8_t)udpPayload;
    }
    uint8_t originalQuestion[271];
    memcpy(originalQuestion, tcpBuf, qend);
    rlen = forwardUpstreamSync(tcpBuf, total);
    if (rlen > 0) { totalAllowed++; if (c) c->allowed++; }
    else {
      memcpy(tcpBuf, originalQuestion, qend);
      rlen = buildServfail(tcpBuf, qend);
    }
  }

  if (rlen > 0) {
    uint8_t lenOut[2] = { (uint8_t)(rlen >> 8), (uint8_t)(rlen & 0xFF) };
    tcpDnsClient.write(lenOut, 2);
    tcpDnsClient.write(tcpBuf, rlen);
  }
  tcpDnsClient.stop();
}

// ---- DHCP server (optional, disabled by default) ----
WiFiUDP dhcpSock;

struct DhcpLease { uint8_t mac[6]; uint32_t ip; uint32_t expires; bool active; };
DhcpLease dhcpLeases[MAX_DHCP_LEASES];

static uint32_t dhcpPoolStart = 0;
static uint32_t dhcpPoolEnd = 0;

static void initDhcpPool() {
  IPAddress local = WiFi.localIP();
  IPAddress gw = WiFi.gatewayIP();
  // Pool: gateway + 100 to gateway + 200 (or local + 100..200 if no gateway)
  uint32_t base = (uint32_t)gw;
  if (base == 0) base = (uint32_t)local;
  dhcpPoolStart = htonl(base) + 100;
  dhcpPoolEnd = htonl(base) + 200;
}

static uint32_t findDhcpLease(const uint8_t* mac) {
  for (int i = 0; i < MAX_DHCP_LEASES; i++)
    if (dhcpLeases[i].active && memcmp(dhcpLeases[i].mac, mac, 6) == 0)
      return dhcpLeases[i].ip;
  return 0;
}
static uint32_t assignDhcpIP(const uint8_t* mac) {
  // Existing lease?
  uint32_t existing = findDhcpLease(mac);
  if (existing) return existing;
  // Find free IP in pool
  for (uint32_t candidate = dhcpPoolStart; candidate <= dhcpPoolEnd; candidate++) {
    bool taken = false;
    for (int i = 0; i < MAX_DHCP_LEASES; i++)
      if (dhcpLeases[i].active && dhcpLeases[i].ip == candidate) { taken = true; break; }
    if (!taken) {
      // Find free lease slot
      for (int i = 0; i < MAX_DHCP_LEASES; i++) {
        if (!dhcpLeases[i].active) {
          memcpy(dhcpLeases[i].mac, mac, 6);
          dhcpLeases[i].ip = candidate;
          dhcpLeases[i].expires = millis() + 86400000UL;  // 24h
          dhcpLeases[i].active = true;
          return candidate;
        }
      }
    }
  }
  return 0;
}

static void handleDhcp() {
  int sz = dhcpSock.parsePacket();
  if (sz <= 0) return;
  uint8_t dhcp[548];
  int len = dhcpSock.read(dhcp, sizeof(dhcp));
  if (len < 240) return;
  if (dhcp[0] != 1) return;  // BOOTREQUEST
  uint32_t xid = (dhcp[4] << 24) | (dhcp[5] << 16) | (dhcp[6] << 8) | dhcp[7];
  uint8_t* mac = dhcp + 28;
  // Magic cookie at offset 236
  if (dhcp[236] != 0x63 || dhcp[237] != 0x82 || dhcp[238] != 0x53 || dhcp[239] != 0x63) return;

  uint8_t msgType = 0;
  int oi = 240;
  while (oi < len && dhcp[oi] != 0xFF) {
    uint8_t opt = dhcp[oi++];
    if (opt == 0) continue;
    if (oi >= len) break;
    uint8_t optLen = dhcp[oi++];
    if (opt == 53 && optLen == 1) msgType = dhcp[oi];
    oi += optLen;
  }
  if (msgType != 1 && msgType != 3) return;  // only DISCOVER and REQUEST

  uint32_t clientIP = assignDhcpIP(mac);
  if (clientIP == 0) return;

  // Build response
  memset(dhcp, 0, 240);
  dhcp[0] = 2;  // BOOTREPLY
  dhcp[1] = 1;  // Ethernet
  dhcp[2] = 6;  // HLEN
  dhcp[4] = (xid >> 24) & 0xFF; dhcp[5] = (xid >> 16) & 0xFF;
  dhcp[6] = (xid >> 8) & 0xFF; dhcp[7] = xid & 0xFF;
  dhcp[10] = 0x80;  // broadcast flag
  // YIADDR (offset 16) = client IP (big-endian)
  dhcp[16] = (clientIP >> 24) & 0xFF; dhcp[17] = (clientIP >> 16) & 0xFF;
  dhcp[18] = (clientIP >> 8) & 0xFF; dhcp[19] = clientIP & 0xFF;
  // SIADDR (offset 20) = our IP
  IPAddress ourIP = WiFi.localIP();
  dhcp[20] = ourIP[0]; dhcp[21] = ourIP[1]; dhcp[22] = ourIP[2]; dhcp[23] = ourIP[3];
  // CHADDR (offset 28) = client MAC
  memcpy(dhcp + 28, mac, 6);
  // Magic cookie
  dhcp[236] = 0x63; dhcp[237] = 0x82; dhcp[238] = 0x53; dhcp[239] = 0x63;

  int o = 240;
  dhcp[o++] = 53; dhcp[o++] = 1; dhcp[o++] = (msgType == 1) ? 2 : 5;  // OFFER or ACK
  dhcp[o++] = 54; dhcp[o++] = 4; dhcp[o++] = ourIP[0]; dhcp[o++] = ourIP[1]; dhcp[o++] = ourIP[2]; dhcp[o++] = ourIP[3];
  IPAddress mask = WiFi.subnetMask();
  dhcp[o++] = 1; dhcp[o++] = 4; dhcp[o++] = mask[0]; dhcp[o++] = mask[1]; dhcp[o++] = mask[2]; dhcp[o++] = mask[3];
  IPAddress gw = WiFi.gatewayIP();
  dhcp[o++] = 3; dhcp[o++] = 4; dhcp[o++] = gw[0]; dhcp[o++] = gw[1]; dhcp[o++] = gw[2]; dhcp[o++] = gw[3];
  // DNS = our IP (so clients use the C3 for DNS)
  dhcp[o++] = 6; dhcp[o++] = 4; dhcp[o++] = ourIP[0]; dhcp[o++] = ourIP[1]; dhcp[o++] = ourIP[2]; dhcp[o++] = ourIP[3];
  // Lease time = 24h (big-endian)
  dhcp[o++] = 51; dhcp[o++] = 4; dhcp[o++] = 0; dhcp[o++] = 0; dhcp[o++] = 0x51; dhcp[o++] = 0x80;
  dhcp[o++] = 0xFF;  // end

  dhcpSock.beginPacket(dhcpSock.remoteIP(), 68);
  dhcpSock.write(dhcp, o);
  dhcpSock.endPacket();
}

// ---- auth (Basic Auth + CSRF token) ----
String authPassword;
String authToken;
bool authEnabled = true;

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static String b64encode(const String& s) {
  String o;
  const uint8_t* in = (const uint8_t*)s.c_str();
  int len = s.length();
  for (int i = 0; i < len; i += 3) {
    uint32_t n = (uint32_t)in[i] << 16;
    if (i + 1 < len) n |= (uint32_t)in[i+1] << 8;
    if (i + 2 < len) n |= in[i+2];
    o += B64[(n >> 18) & 0x3F];
    o += B64[(n >> 12) & 0x3F];
    o += (i + 1 < len) ? B64[(n >> 6) & 0x3F] : '=';
    o += (i + 2 < len) ? B64[n & 0x3F] : '=';
  }
  return o;
}
static void genRandomToken(String& token) {
  token = "";
  for (int i = 0; i < 4; i++) {
    char part[9];
    snprintf(part, sizeof(part), "%08lx", (unsigned long)esp_random());
    token += part;
  }
}
static void genRandomPassword() {
  const char chars[] = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
  authPassword = "";
  for (int i = 0; i < 10; i++)
    authPassword += chars[esp_random() % (sizeof(chars) - 1)];
  genRandomToken(authToken);
  authPasswordGenerated = true;
}
static void loadAuth() {
  bool hadConfig = false;
  bool authWasDisabled = false;
  bool needsSave = false;
  File f = LittleFS.open("/auth.cfg", "r");
  if (f) {
    hadConfig = true;
    authPassword = f.readStringUntil('\n'); authPassword.trim();
    authToken = f.readStringUntil('\n'); authToken.trim();
    String enabledLine = f.readStringUntil('\n'); enabledLine.trim();
    if (enabledLine.length() > 0) authEnabled = (enabledLine != "0");
    authWasDisabled = !authEnabled;
    f.close();
  }
  if (authPassword.length() == 0) {
    genRandomPassword();
    needsSave = true;
  }
  if (authToken.length() < 32) { genRandomToken(authToken); needsSave = true; }
  authEnabled = true;
  if (!hadConfig || authWasDisabled) needsSave = true;
  if (needsSave && !saveAuthCfg())
    LOGN("[cfg] ERROR: could not persist authentication settings");
}
static bool saveAuthCfg() {
  File fo = LittleFS.open("/auth.new", "w");
  if (!fo) return false;
  fo.println(authPassword); fo.println(authToken); fo.println("1");
  bool ok = fo.getWriteError() == 0;
  fo.close();
  if (!ok) { LittleFS.remove("/auth.new"); return false; }
  return replaceStagedFile("/auth.cfg", "/auth.new", "/auth.bak");
}
static bool checkAuth() {
  if (!authEnabled) return true;
  String expected = "Basic " + b64encode("admin:" + authPassword);
  return web.header("Authorization") == expected;
}
static bool checkToken() {
  return web.header("X-CSRF-Token").length() == authToken.length() &&
         web.header("X-CSRF-Token") == authToken;
}
static void requireAuth() {
  web.sendHeader("WWW-Authenticate", "Basic realm=\"C3 AdBlock\"");
  web.send(401, "text/plain", "auth required");
}

// ---- web server ----

static String macStr(const uint8_t* m) {
  char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]);
  return String(s);
}
static String jesc(const String& s) {
  String o;
  const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < s.length(); i++) {
    unsigned char ch = (unsigned char)s[i];
    if (ch == '"' || ch == '\\') { o += '\\'; o += (char)ch; }
    else if (ch == '\b') o += "\\b";
    else if (ch == '\f') o += "\\f";
    else if (ch == '\n') o += "\\n";
    else if (ch == '\r') o += "\\r";
    else if (ch == '\t') o += "\\t";
    else if (ch < 0x20) {
      o += "\\u00";
      o += hex[ch >> 4];
      o += hex[ch & 0x0F];
    } else o += (char)ch;
  }
  return o;
}

static void handleRoot() {
  if (!checkAuth()) { requireAuth(); return; }
  if (web.header("If-None-Match") == DASHBOARD_ETAG) { web.send(304); return; }
  web.sendHeader("Cache-Control", "max-age=3600");
  web.sendHeader("ETag", DASHBOARD_ETAG);
  web.send_P(200, "text/html", PAGE);
}

static void handleStats() {
  if (!checkAuth()) { requireAuth(); return; }
  web.sendHeader("Cache-Control", "no-store");
  uint32_t up = millis() / 1000;
  char ut[24];
  snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  String bloomStr = bloomFilter ? (String(bloomBits / 8 / 1024) + " KB") : String("off");

  String j = "{\"blocked\":" + String(totalBlocked) +
             ",\"allowed\":" + totalAllowed + ",\"domains\":" + numHashes +
             ",\"customCount\":" + numCustom + ",\"rewriteCount\":" + numRewrites +
             ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"bloom\":\"" + jesc(bloomStr) + "\",\"pending\":" + pendingCount +
             ",\"dhcp\":" + (dhcpEnabled ? "true" : "false") +
             ",\"auth\":true,\"paused\":" + (paused ? "true" : "false") +
             ",\"blocklistValid\":" + (blocklistValid ? "true" : "false") +
             ",\"blocklistReadError\":" + (blocklistReadError ? "true" : "false") +
             ",\"clients\":" + numClients + ",\"upstat\":\"" + jesc(updateStatus) + "\"}";
  web.send(200, "application/json", j);
}

static void handleCsrfToken() {
  if (!checkAuth()) { requireAuth(); return; }
  web.sendHeader("Cache-Control", "no-store");
  web.send(200, "text/plain", authToken);
}

static void handleDashboardData() {
  if (!checkAuth()) { requireAuth(); return; }
  web.sendHeader("Cache-Control", "no-store");
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"upurl\":\"" +
             jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"clients\":[";
  for (int i = 0; i < numClients; i++) {
    Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : "");
    j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) +
         "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed +
         ",\"banned\":" + (c.banned ? "true" : "false") + "}";
  }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "],\"rewrites\":[";
  for (int i = 0; i < numRewrites; i++) {
    j += (i ? "," : "");
    j += "{\"domain\":\"" + jesc(rewrites[i].domain) + "\",\"ip\":\"" +
         rewrites[i].address.toString() + "\"}";
  }
  j += "]}";
  web.send(200, "application/json", j);
}

static void handleAddRewrite() {
  if (!checkAuth()) { requireAuth(); return; }
  if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
  if (!addRewrite(web.arg("d"), web.arg("ip"))) {
    web.send(400, "text/plain", "invalid domain or IPv4 address, full table, or storage failure");
    return;
  }
  web.send(200, "text/plain", "ok");
}

static void handleRemoveRewrite() {
  if (!checkAuth()) { requireAuth(); return; }
  if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
  if (!removeRewrite(web.arg("d"))) {
    web.send(404, "text/plain", "rewrite not found or storage failure");
    return;
  }
  web.send(200, "text/plain", "ok");
}

static void handlePauseResume() {
  if (!checkAuth()) { requireAuth(); return; }
  if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
  bool previous = paused;
  paused = web.arg("paused") == "1";
  clearDecisionCache();
  if (!savePausedCfg()) {
    paused = previous;
    clearDecisionCache();
    web.send(500, "text/plain", "failed to persist pause state");
    return;
  }
  web.send(200, "text/plain", paused ? "paused" : "resumed");
}

static void handleBan() {
  if (!checkAuth()) { requireAuth(); return; }
  if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
  IPAddress ip;
  if (ip.fromString(web.arg("ip"))) {
    uint32_t ipraw = (uint32_t)ip;
    Dev* c = getClient(ipraw);
    bool wasBanned = isBannedIP(ipraw);
    bool changed = wasBanned ? removeBannedIP(ipraw) : addBannedIP(ipraw);
    if (!changed || !saveBanned()) {
      if (changed) {
        if (wasBanned) addBannedIP(ipraw); else removeBannedIP(ipraw);
      }
      if (c) c->banned = wasBanned;
      web.send(500, "text/plain", "failed to persist ban state");
      return;
    }
    if (c) c->banned = !wasBanned;
  } else {
    web.send(400, "text/plain", "invalid IP address");
    return;
  }
  web.send(200, "text/plain", "ok");
}

static void handleAddBlock() {
  if (!checkAuth()) { requireAuth(); return; }
  if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
  if (!addCustom(web.arg("d"))) {
    web.send(400, "text/plain", "invalid, duplicate, full, or storage failure");
    return;
  }
  web.send(200, "text/plain", "ok");
}
static void handleUnblock() {
  if (!checkAuth()) { requireAuth(); return; }
  if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
  if (!removeCustom(web.arg("d"))) {
    web.send(404, "text/plain", "domain not found or storage failure");
    return;
  }
  web.send(200, "text/plain", "ok");
}

static void handleDhcpToggle() {
  if (!checkAuth()) { requireAuth(); return; }
  if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
  bool previous = dhcpEnabled;
  dhcpEnabled = !dhcpEnabled;
  if (!saveDhcpCfg()) {
    dhcpEnabled = previous;
    web.send(500, "text/plain", "failed to persist DHCP state");
    return;
  }
  if (dhcpEnabled) {
    initDhcpPool();
    dhcpSock.begin(DHCP_PORT);
    web.send(200, "text/plain", "DHCP enabled — disable your router's DHCP!");
  } else {
    dhcpSock.stop();
    web.send(200, "text/plain", "DHCP disabled");
  }
}

static void handleSetWifi() {
  if (!checkAuth()) { requireAuth(); return; }
  if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
  String ssid = web.arg("ssid");
  String pass = web.arg("pass");
  if (ssid.length() == 0) { web.send(400, "text/plain", "missing ssid"); return; }
  if (!saveWifiCfg(ssid, pass)) {
    web.send(500, "text/plain", "failed to persist WiFi settings");
    return;
  }
  web.send(200, "text/plain", "saved — rebooting...");
  delay(500);
  ESP.restart();
}

static void handleSetPassword() {
  if (!checkAuth()) { requireAuth(); return; }
  if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
  String current = web.arg("current");
  String newPass = web.arg("newpass");
  String confirm = web.arg("confirm");
  if (newPass.length() == 0) {
    web.send(400, "text/plain", "missing new password");
    return;
  }
  if (authEnabled) {
    if (current.length() == 0) {
      web.send(400, "text/plain", "current password required");
      return;
    }
    if (current != authPassword) {
      web.send(403, "text/plain", "current password incorrect");
      return;
    }
  }
  if (newPass.length() < 6) {
    web.send(400, "text/plain", "new password must be at least 6 characters");
    return;
  }
  if (newPass != confirm) {
    web.send(400, "text/plain", "new password and confirmation do not match");
    return;
  }
  String previousPassword = authPassword;
  authPassword = newPass;
  if (!saveAuthCfg()) {
    authPassword = previousPassword;
    web.send(500, "text/plain", "failed to persist password");
    return;
  }
  ArduinoOTA.setPassword(authPassword.c_str());
  web.send(200, "text/plain", "password changed successfully");
  LOGN("[cfg] dashboard password updated");
}

static void handleFactoryReset() {
  if (!checkAuth()) { requireAuth(); return; }
  if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
  String confirm = web.arg("confirm");
  if (confirm != "RESET") {
    web.send(400, "text/plain", "type RESET to confirm factory reset");
    return;
  }
  LOGN("[reset] erasing all config files...");
  LittleFS.remove("/auth.cfg");
  LittleFS.remove("/wifi.cfg");
  LittleFS.remove("/custom.txt");
  LittleFS.remove("/rewrites.txt");
  LittleFS.remove("/banned.txt");
  LittleFS.remove("/update.cfg");
  LittleFS.remove("/dhcp.cfg");
  LittleFS.remove("/blocklist.bin");
  LittleFS.remove("/blocklist.new");
  LittleFS.remove(BLOCKLIST_BACKUP_PATH);
  LittleFS.remove("/paused.cfg");
  LittleFS.remove("/auth.new"); LittleFS.remove("/auth.bak");
  LittleFS.remove("/wifi.new"); LittleFS.remove("/wifi.bak");
  LittleFS.remove("/custom.new"); LittleFS.remove("/custom.bak");
  LittleFS.remove("/rewrites.new"); LittleFS.remove("/rewrites.bak");
  LittleFS.remove("/banned.new"); LittleFS.remove("/banned.bak");
  LittleFS.remove("/update.new"); LittleFS.remove("/update.bak");
  LittleFS.remove("/dhcp.new"); LittleFS.remove("/dhcp.bak");
  LittleFS.remove("/paused.new"); LittleFS.remove("/paused.bak");
  web.send(200, "text/plain", "factory reset done — rebooting...");
  delay(500);
  ESP.restart();
}

// ---- blocklist swap (shared by upload + remote fetch) ----
static uint32_t crc32Update(uint32_t crc, uint8_t byte) {
  crc ^= byte;
  for (uint8_t bit = 0; bit < 8; bit++)
    crc = (crc >> 1) ^ (0xEDB88320UL & (0U - (crc & 1U)));
  return crc;
}

static bool loadBloomFromBlocklist(File& f) {
  if (bloomFilter) { free(bloomFilter); bloomFilter = nullptr; }
  bloomBits = 0; bloomK = 0; numHashes = 0; hashTableOffset = 0;
  memset(prefixIndex, 0, sizeof(prefixIndex));
  clearDecisionCache();
  if (!f) return false;
  uint8_t hdr[BL_HEADER_SIZE];
  f.seek(0);
  if (!f.seek(0) || f.read(hdr, BL_HEADER_SIZE) != BL_HEADER_SIZE ||
      memcmp(hdr, BL_MAGIC, 4) != 0 || (hdr[4] != BL_VERSION && hdr[4] != 1) ||
      hdr[5] != HASH_BYTES) return false;

  uint32_t count = (uint32_t)hdr[6] | ((uint32_t)hdr[7] << 8) |
                   ((uint32_t)hdr[8] << 16) | ((uint32_t)hdr[9] << 24);
  uint32_t bits = (uint32_t)hdr[10] | ((uint32_t)hdr[11] << 8) |
                  ((uint32_t)hdr[12] << 16) | ((uint32_t)hdr[13] << 24);
  uint8_t k = hdr[14];
  if ((bits == 0 && k != 0) || (bits != 0 && (k == 0 || k > 30)) ||
      bits > 2097152) return false;
  uint64_t bloomBytes = ((uint64_t)bits + 7) / 8;
  uint64_t expected = BL_HEADER_SIZE + bloomBytes + (uint64_t)count * HASH_BYTES;
  if (expected != f.size()) return false;

  uint32_t tableOffset = BL_HEADER_SIZE + (uint32_t)bloomBytes;
  uint8_t* newBloom = nullptr;
  uint32_t crc = 0xFFFFFFFFUL;
  if (bits) {
    newBloom = (uint8_t*)malloc((size_t)bloomBytes);
    if (newBloom && (!f.seek(BL_HEADER_SIZE) || f.read(newBloom, (size_t)bloomBytes) != bloomBytes)) {
      free(newBloom);
      return false;
    }
    if (newBloom) {
      for (uint32_t i = 0; i < bloomBytes; i++) crc = crc32Update(crc, newBloom[i]);
    } else {
      uint8_t chunk[128];
      uint32_t remaining = (uint32_t)bloomBytes;
      if (!f.seek(BL_HEADER_SIZE)) return false;
      while (remaining) {
        size_t amount = remaining > sizeof(chunk) ? sizeof(chunk) : remaining;
        if (f.read(chunk, amount) != amount) return false;
        for (size_t i = 0; i < amount; i++) crc = crc32Update(crc, chunk[i]);
        remaining -= amount;
      }
    }
  }

  uint8_t bytes[HASH_BYTES];
  uint64_t previous = 0;
  uint32_t nextPrefix = 0;
  if (!f.seek(tableOffset)) { if (newBloom) free(newBloom); return false; }
  for (uint32_t i = 0; i < count; i++) {
    if (f.read(bytes, HASH_BYTES) != HASH_BYTES) {
      if (newBloom) free(newBloom);
      return false;
    }
    for (int j = 0; j < HASH_BYTES; j++) crc = crc32Update(crc, bytes[j]);
    uint64_t value = 0;
    for (int j = 0; j < HASH_BYTES; j++) value |= (uint64_t)bytes[j] << (8 * j);
    if (i && value < previous) {
      if (newBloom) free(newBloom);
      return false;
    }
    uint32_t prefix = (uint32_t)(value >> 32);
    while (nextPrefix <= prefix) prefixIndex[nextPrefix++] = i;
    previous = value;
  }
  while (nextPrefix <= 256) prefixIndex[nextPrefix++] = count;
  if (hdr[4] == BL_VERSION) {
    crc ^= 0xFFFFFFFFUL;
    uint32_t expectedCrc = (uint32_t)hdr[15] | ((uint32_t)hdr[16] << 8) |
                           ((uint32_t)hdr[17] << 16) | ((uint32_t)hdr[18] << 24);
    if (crc != expectedCrc || hdr[19] != 0) {
      if (newBloom) free(newBloom);
      return false;
    }
  }

  numHashes = count;
  bloomBits = newBloom ? bits : 0;
  bloomK = newBloom ? k : 0;
  bloomFilter = newBloom;
  hashTableOffset = tableOffset;
  if (bits && !newBloom) LOGN("[bl] bloom malloc failed — exact flash lookup enabled");
  return true;
}

static void reopenBlocklist() {
  if (blocklist) blocklist.close();
  blocklistReadError = false;
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (!loadBloomFromBlocklist(blocklist)) {
    if (blocklist) blocklist.close();
    numHashes = 0;
    hashTableOffset = 0;
    bloomBits = 0;
    bloomK = 0;
    blocklistValid = false;
    LOGN("[bl] invalid blocklist; blocking disabled");
  } else blocklistValid = true;
  if (blocklist) LOG("[bl] %u domains, bloom %u bits k=%u\n", numHashes, bloomBits, bloomK);
}
static void beginBlocklistSwap() {
  LittleFS.remove("/blocklist.new");
}
static bool commitNewBlocklist() {
  File f = LittleFS.open("/blocklist.new", "r");
  bool ok = f && loadBloomFromBlocklist(f);
  if (f) f.close();
  if (bloomFilter) { free(bloomFilter); bloomFilter = nullptr; }
  numHashes = 0;
  bloomBits = bloomK = 0;
  hashTableOffset = 0;

  if (ok) {
    if (blocklist) blocklist.close();
    LittleFS.remove(BLOCKLIST_BACKUP_PATH);
    bool hadActive = LittleFS.exists(BLOCKLIST_PATH);
    bool savedOld = !hadActive || LittleFS.rename(BLOCKLIST_PATH, BLOCKLIST_BACKUP_PATH);
    ok = savedOld && LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
    if (!ok && hadActive && LittleFS.exists(BLOCKLIST_BACKUP_PATH))
      LittleFS.rename(BLOCKLIST_BACKUP_PATH, BLOCKLIST_PATH);
    if (ok) LittleFS.remove(BLOCKLIST_BACKUP_PATH);
  }
  if (!ok) LittleFS.remove("/blocklist.new");
  reopenBlocklist();
  clearDecisionCache();
  return ok;
}

// ---- OTA blocklist update (browser upload) ----
static bool upOk = false;
static bool upFailed = false;
static File upFile;
static void handleUploadDone() {
  if (!checkAuth()) { requireAuth(); return; }
  if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
  web.send(upOk ? 200 : 500, "text/plain",
           upOk ? "ok" : "rejected: invalid blocklist (bad magic/version/size)");
}
static void handleUpload() {
  if (!checkAuth()) { requireAuth(); return; }
  if (!checkToken()) {
    if (web.upload().status == UPLOAD_FILE_START) upOk = false;
    return;
  }
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upOk = false; upFailed = false; beginBlocklistSwap();
      upFile = LittleFS.open("/blocklist.new", "w");
      if (!upFile) upFailed = true;
      LOG("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (!upFile || upFailed) break;
      {
        size_t totalFs = LittleFS.totalBytes();
        size_t usedFs = LittleFS.usedBytes();
        if (usedFs > totalFs || u.currentSize > totalFs - usedFs ||
            upFile.write(u.buf, u.currentSize) != u.currentSize)
          upFailed = true;
      }
      break;
    case UPLOAD_FILE_END:
      if (upFile) upFile.close();
      if (!upFailed) upOk = commitNewBlocklist();
      else {
        LittleFS.remove("/blocklist.new");
        reopenBlocklist();
      }
      LOG("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (upFile) upFile.close();
      LittleFS.remove("/blocklist.new"); reopenBlocklist();
      LOGN("[ota] aborted");
      break;
  }
}

// ---- remote blocklist auto-update ----

static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r");
  if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim();
  if (iv.length()) updateIntervalH = iv.toInt();
  f.close();
  if (updateIntervalH < 1) updateIntervalH = 1;
  if (updateIntervalH > 1193) updateIntervalH = 1193;
}
static bool saveUpdateCfg() {
  File f = LittleFS.open("/update.new", "w");
  if (!f) return false;
  f.println(updateUrl); f.println(updateIntervalH);
  bool ok = f.getWriteError() == 0;
  f.close();
  if (!ok) { LittleFS.remove("/update.new"); return false; }
  return replaceStagedFile("/update.cfg", "/update.new", "/update.bak");
}
static bool fetchBlocklist(String url) {
  url.trim();
  if (!url.length()) { updateStatus = "no url set"; return false; }
  if (!url.startsWith("https://")) {
    updateStatus = "HTTPS URL required";
    return false;
  }
  LOG("[remote] GET %s\n", url.c_str());
  WiFiClientSecure cs;
  // Do not disable certificate verification; the core's trust store must be provisioned.
  HTTPClient http;
  http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
  if (!http.begin(cs, url)) {
    updateStatus = "begin failed"; return false;
  }
  int code = http.GET();
  if (code != HTTP_CODE_OK) {
    http.end(); updateStatus = "HTTP " + String(code);
    LOG("[remote] %s\n", updateStatus.c_str());
    return false;
  }
  beginBlocklistSwap();
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) { http.end(); updateStatus = "fs open failed"; reopenBlocklist(); return false; }
  WiFiClient* stream = http.getStreamPtr();
  int len = http.getSize();
  uint8_t b[1024];
  size_t total = 0;
  bool writeFailed = false;
  uint32_t idle = millis();
  while (http.connected() && (len < 0 || (int)total < len)) {
    size_t avail = stream->available();
    if (avail) {
      int n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail);
      if (n > 0) {
        size_t totalFs = LittleFS.totalBytes();
        size_t usedFs = LittleFS.usedBytes();
        if (usedFs > totalFs || (size_t)n > totalFs - usedFs ||
            f.write(b, n) != (size_t)n) {
          writeFailed = true;
          break;
        }
        total += (size_t)n;
        idle = millis();
      }
    } else {
      if (millis() - idle > 15000) { writeFailed = true; break; }
      delay(2);
    }
  }
  f.close(); http.end();
  bool complete = !writeFailed && (len < 0 || total == (size_t)len);
  if (!complete) {
    LittleFS.remove("/blocklist.new");
    reopenBlocklist();
  }
  bool ok = complete && commitNewBlocklist();
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains") : ("bad data (" + String(total) + "B)");
  LOG("[remote] %s\n", updateStatus.c_str());
  return ok;
}

// ---- firmware OTA ----
static bool fwUploadOk = false;
static bool fwUploadFailed = false;
static void handleFwUpdateDone() {
  if (!checkAuth()) { requireAuth(); return; }
  if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
  bool ok = fwUploadOk && !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  if (!checkAuth()) { requireAuth(); return; }
  if (!checkToken()) {
    if (web.upload().status == UPLOAD_FILE_START) {
      fwUploadOk = false;
      fwUploadFailed = true;
      Update.abort();
    }
    return;
  }
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwUploadOk = false;
    fwUploadFailed = false;
    LOG("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) {
      fwUploadFailed = true;
      Update.printError(Serial);
    }
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (!fwUploadFailed && Update.write(u.buf, u.currentSize) != u.currentSize) {
      fwUploadFailed = true;
      Update.abort();
      Update.printError(Serial);
    }
  } else if (u.status == UPLOAD_FILE_END) {
    if (!fwUploadFailed && Update.end(true)) {
      fwUploadOk = true;
      LOG("[fw-ota] %u bytes OK\n", u.totalSize);
    } else {
      fwUploadFailed = true;
      Update.abort();
      Update.printError(Serial);
    }
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    fwUploadOk = false;
    fwUploadFailed = true;
    Update.abort(); LOGN("[fw-ota] aborted");
  }
}

// ---- WiFi config ----
static bool loadWifiCfg(String& ssid, String& pass) {
  File f = LittleFS.open("/wifi.cfg", "r");
  if (!f) return false;
  ssid = f.readStringUntil('\n'); ssid.trim();
  pass = f.readStringUntil('\n'); pass.trim();
  f.close();
  return ssid.length() > 0;
}
static bool saveWifiCfg(const String& ssid, const String& pass) {
  File f = LittleFS.open("/wifi.new", "w");
  if (!f) return false;
  f.println(ssid); f.println(pass);
  bool ok = f.getWriteError() == 0;
  f.close();
  if (!ok) { LittleFS.remove("/wifi.new"); return false; }
  return replaceStagedFile("/wifi.cfg", "/wifi.new", "/wifi.bak");
}

static bool connectWiFi() {
  String ssid, pass;
  bool hasCfg = loadWifiCfg(ssid, pass);

  // Try saved config first, then secrets.h
  const char* trySsid = nullptr;
  const char* tryPass = nullptr;
  if (hasCfg) { trySsid = ssid.c_str(); tryPass = pass.c_str(); }
  else if (String(WIFI_SSID) != "YOUR_WIFI_SSID") { trySsid = WIFI_SSID; tryPass = WIFI_PASS; }

  if (!trySsid) return false;

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.begin(trySsid, tryPass);
  LOG("WiFi: connecting to %s", trySsid);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && (millis() - t0) < 15000) {
    delay(300); Serial.print(".");
  }
  if (WiFi.status() == WL_CONNECTED) {
    LOGN("\nWiFi up: " + WiFi.localIP().toString());
    return true;
  }
  LOGN("\nWiFi connect failed");
  WiFi.disconnect();
  return false;
}

// ---- captive portal ----
static WiFiUDP captiveDns;

static void handleCaptiveDns() {
  int sz = captiveDns.parsePacket();
  if (sz <= 0) return;
  IPAddress cip = captiveDns.remoteIP();
  uint16_t cport = captiveDns.remotePort();
  int qlen = captiveDns.read(dnsBuf, sizeof(dnsBuf));
  if (qlen < 13) return;
  // Respond to A queries with the setup AP address.
  char domain[256]; uint16_t qtype; int qend;
  bool hasEdns; uint16_t udpPayload, ednsFlags;
  if (!parseDnsQuery(dnsBuf, qlen, domain, &qtype, &qend, &hasEdns,
                     &udpPayload, &ednsFlags, DNS_BUF_SIZE) || qtype != 1 ||
      qend + 16 > DNS_BUF_SIZE) return;
  {
    uint8_t rd = dnsBuf[2] & 0x01;
    uint8_t cd = dnsBuf[3] & 0x10;
    dnsBuf[2] = 0x80 | rd; dnsBuf[3] = 0x80 | cd;
    dnsBuf[6] = 0; dnsBuf[7] = 1;
    dnsBuf[8] = 0; dnsBuf[9] = 0; dnsBuf[10] = 0; dnsBuf[11] = 0;
    uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,0,60, 0,4, 192,168,4,1};
    memcpy(dnsBuf + qend, ans, sizeof(ans));
    int rlen = appendResponseOpt(dnsBuf, qend + sizeof(ans), hasEdns, udpPayload, ednsFlags);
    if (!rlen) return;
    captiveDns.beginPacket(cip, cport);
    captiveDns.write(dnsBuf, rlen);
    captiveDns.endPacket();
  }
}

static void runCaptivePortal() {
  WiFi.mode(WIFI_AP);
  WiFi.softAP("C3AdBlock-Setup");
  genRandomToken(captiveToken);
  LOGN("\n[captive] AP: C3AdBlock-Setup — connect and open http://192.168.4.1");
  captiveDns.begin(53);
  web.on("/", []() {
    String html((const __FlashStringHelper*)PORTAL_HTML);
    html.replace("__CSRF__", captiveToken);
    web.send(200, "text/html", html);
  });
  web.on("/generate_204", []() { web.send(204); });  // Android captive detection
  web.on("/save-wifi", HTTP_POST, []() {
    if (web.arg("csrf") != captiveToken) {
      web.send(403, "text/html", "<h1>Invalid setup token</h1>");
      return;
    }
    String ssid = web.arg("ssid");
    String pass = web.arg("pass");
    if (ssid.length() == 0) { web.send(400, "text/html", "<h1>Missing SSID</h1>"); return; }
    if (!saveWifiCfg(ssid, pass)) {
      web.send(500, "text/html", "<h1>Could not save WiFi settings</h1>");
      return;
    }
    web.send(200, "text/html", "<h1>Saved! Rebooting...</h1><p>Connect to your WiFi and find the device at c3adblock.local</p>");
    delay(1500);
    ESP.restart();
  });
  web.begin();

  while (true) {
    web.handleClient();
    handleCaptiveDns();
    delay(2);
  }
}

// ---- DHCP config persistence ----
static void loadDhcpCfg() {
  File f = LittleFS.open("/dhcp.cfg", "r");
  if (!f) return;
  String v = f.readStringUntil('\n'); v.trim();
  dhcpEnabled = (v == "1");
  f.close();
}
static bool saveDhcpCfg() {
  File f = LittleFS.open("/dhcp.new", "w");
  if (!f) return false;
  f.println(dhcpEnabled ? "1" : "0");
  bool ok = f.getWriteError() == 0;
  f.close();
  if (!ok) { LittleFS.remove("/dhcp.new"); return false; }
  return replaceStagedFile("/dhcp.cfg", "/dhcp.new", "/dhcp.bak");
}

static void loadPausedCfg() {
  File f = LittleFS.open("/paused.cfg", "r");
  if (!f) { paused = false; return; }
  String value = f.readStringUntil('\n');
  value.trim();
  paused = value == "1";
  f.close();
}
static bool savePausedCfg() {
  File f = LittleFS.open("/paused.new", "w");
  if (!f) { LOGN("[cfg] failed to persist pause state"); return false; }
  f.println(paused ? "1" : "0");
  bool ok = f.getWriteError() == 0;
  f.close();
  if (!ok) { LittleFS.remove("/paused.new"); return false; }
  return replaceStagedFile("/paused.cfg", "/paused.new", "/paused.bak");
}

// ---- setup / loop ----
void setup() {
  Serial.begin(115200);
  delay(300);
  LOGN("\n[c3-adblock] booting");

  if (!LittleFS.begin(true)) LOGN("LittleFS FAILED");

  recoverConfigFile("/auth.cfg", "/auth.new", "/auth.bak");
  recoverConfigFile("/wifi.cfg", "/wifi.new", "/wifi.bak");
  recoverConfigFile("/custom.txt", "/custom.new", "/custom.bak");
  recoverConfigFile("/rewrites.txt", "/rewrites.new", "/rewrites.bak");
  recoverConfigFile("/banned.txt", "/banned.new", "/banned.bak");
  recoverConfigFile("/update.cfg", "/update.new", "/update.bak");
  recoverConfigFile("/dhcp.cfg", "/dhcp.new", "/dhcp.bak");
  recoverConfigFile("/paused.cfg", "/paused.new", "/paused.bak");
  loadAuth();
  loadCustom();
  loadRewrites();
  loadBanned();
  loadUpdateCfg();
  loadDhcpCfg();
  loadPausedCfg();
  if (!LittleFS.exists(BLOCKLIST_PATH) && LittleFS.exists(BLOCKLIST_BACKUP_PATH))
    LittleFS.rename(BLOCKLIST_BACKUP_PATH, BLOCKLIST_PATH);
  else if (LittleFS.exists(BLOCKLIST_PATH))
    LittleFS.remove(BLOCKLIST_BACKUP_PATH);
  reopenBlocklist();
  LOG("[cfg] custom:%d rewrites:%d banned:%d auth:enabled\n", numCustom, numRewrites, numBanned);
  if (authPasswordGenerated) LOGN("[cfg] dashboard password (save securely): " + authPassword);

  if (!connectWiFi()) {
    runCaptivePortal();  // blocks forever (reboots on save)
    return;
  }

  if (MDNS.begin("c3adblock")) {
    MDNS.addService("http", "tcp", 80);
    LOGN("dashboard: http://c3adblock.local");
  }

  dnsServer.begin(DNS_PORT);
  upstream.begin(0);
  tcpUpstream.begin(0);
  tcpDnsServer.begin();
  web.collectHeaders(COLLECTED_HEADERS, sizeof(COLLECTED_HEADERS) / sizeof(char*));
  web.on("/", handleRoot);
  web.on("/stats.json", handleStats);
  web.on("/csrf", handleCsrfToken);
  web.on("/dashboard-data.json", handleDashboardData);
  web.on("/ban", HTTP_POST, handleBan);
  web.on("/addblock", HTTP_POST, handleAddBlock);
  web.on("/unblock", HTTP_POST, handleUnblock);
  web.on("/addrewrite", HTTP_POST, handleAddRewrite);
  web.on("/removerewrite", HTTP_POST, handleRemoveRewrite);
  web.on("/pause", HTTP_POST, handlePauseResume);
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);
  web.on("/fetchnow", HTTP_POST, []() {
    if (!checkAuth()) { requireAuth(); return; }
    if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
    fetchBlocklist(updateUrl);
    web.send(200, "text/plain", updateStatus);
  });
  web.on("/setupdate", HTTP_POST, []() {
    if (!checkAuth()) { requireAuth(); return; }
    if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
    String previousUrl = updateUrl;
    uint32_t previousInterval = updateIntervalH;
    if (web.hasArg("u")) updateUrl = web.arg("u");
    if (web.hasArg("h")) {
      updateIntervalH = web.arg("h").toInt();
      if (updateIntervalH < 1) updateIntervalH = 1;
      if (updateIntervalH > 1193) updateIntervalH = 1193;
    }
    if (updateUrl.length() > 256 ||
        (updateUrl.length() && !updateUrl.startsWith("https://"))) {
      updateUrl = previousUrl;
      updateIntervalH = previousInterval;
      web.send(400, "text/plain", "HTTPS URL required (maximum 256 characters)");
      return;
    }
    if (!saveUpdateCfg()) {
      updateUrl = previousUrl;
      updateIntervalH = previousInterval;
      web.send(500, "text/plain", "failed to persist update settings");
      return;
    }
    web.send(200, "text/plain", "ok");
  });
  web.on("/dhcp", HTTP_POST, handleDhcpToggle);
  web.on("/setwifi", HTTP_POST, handleSetWifi);
  web.on("/setpassword", HTTP_POST, handleSetPassword);
  web.on("/factoryreset", HTTP_POST, handleFactoryReset);
  web.begin();

  ArduinoOTA.setHostname("c3adblock");
  ArduinoOTA.setPassword(authPassword.c_str());
  ArduinoOTA.begin();

  if (dhcpEnabled) {
    initDhcpPool();
    dhcpSock.begin(DHCP_PORT);
    LOGN("DHCP server enabled on :67");
  }

  LOGN("DNS :53 (UDP+TCP) + dashboard :80 + OTA up");
}

void loop() {
  ArduinoOTA.handle();
  web.handleClient();
  handleDns();
  pollUpstream(dnsBuf, DNS_BUF_SIZE);
  expirePending();
  handleTcpDns();
  if (dhcpEnabled) handleDhcp();

  // Track DNS activity for idle-gated remote fetch (set in handleDns/pollUpstream)
  if (pendingCount > 0) lastDnsActivityMs = millis();

  // Idle-gated remote blocklist auto-update (only when DNS has been quiet)
  if (updateUrl.length() && numHashes > 0) {
    uint32_t now = millis();
    if (lastCheckMs == 0) {
      lastCheckMs = now;  // skip immediate fetch on boot
    } else if ((now - lastCheckMs) >= updateIntervalH * 3600000UL &&
               (now - lastDnsActivityMs) >= REMOTE_FETCH_IDLE_MS) {
      lastCheckMs = now;
      fetchBlocklist(updateUrl);
    }
  }
}
