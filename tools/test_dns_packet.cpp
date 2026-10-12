#include <cassert>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "../src/dns_packet.h"

static std::vector<uint8_t> makeQuery(const std::string& name, uint16_t type,
                                      bool edns = false) {
  std::vector<uint8_t> packet(12, 0);
  packet[2] = 0x01;
  packet[5] = 1;
  packet[11] = edns ? 1 : 0;
  size_t start = 0;
  while (start < name.size()) {
    size_t end = name.find('.', start);
    if (end == std::string::npos) end = name.size();
    packet.push_back(static_cast<uint8_t>(end - start));
    packet.insert(packet.end(), name.begin() + start, name.begin() + end);
    start = end + 1;
  }
  packet.push_back(0);
  packet.push_back(static_cast<uint8_t>(type >> 8));
  packet.push_back(static_cast<uint8_t>(type));
  packet.push_back(0);
  packet.push_back(1);
  if (edns) {
    const uint8_t opt[] = {0, 0, 41, 0x10, 0x00, 0, 0, 0x80, 0, 0, 0};
    packet.insert(packet.end(), opt, opt + sizeof(opt));
  }
  return packet;
}

static bool parses(const std::vector<uint8_t>& packet, uint16_t expectedType,
                   const char* expectedName, bool expectedEdns = false,
                   uint16_t expectedPayload = 512, uint16_t expectedFlags = 0) {
  char name[254] = {};
  uint16_t type = 0, payload = 0, flags = 0;
  int questionEnd = 0;
  bool hasEdns = false;
  size_t length = parseDnsQuery(packet.data(), static_cast<int>(packet.size()),
                                name, &type, &questionEnd, &hasEdns, &payload,
                                &flags, 1232);
  return length != 0 && type == expectedType &&
         std::strcmp(name, expectedName) == 0 &&
         questionEnd <= static_cast<int>(packet.size()) &&
         hasEdns == expectedEdns && payload == expectedPayload &&
         flags == expectedFlags;
}

int main() {
  auto a = makeQuery("www.Example.com", 1);
  assert(parses(a, 1, "example.com"));

  auto aaaa = makeQuery("example.com", 28);
  assert(parses(aaaa, 28, "example.com"));

  auto https = makeQuery("service.example", 65);
  assert(parses(https, 65, "service.example"));

  auto edns = makeQuery("example.com", 65, true);
  assert(parses(edns, 65, "example.com", true, 1232, 0x8000));

  auto smallEdns = edns;
  smallEdns[smallEdns.size() - 8] = 0;
  smallEdns[smallEdns.size() - 7] = 1;
  assert(parses(smallEdns, 65, "example.com", true, 512, 0x8000));

  auto optionEdns = makeQuery("example.com", 65, true);
  optionEdns[optionEdns.size() - 1] = 4;
  optionEdns.insert(optionEdns.end(), {0, 8, 0, 0});
  assert(parses(optionEdns, 65, "example.com", true, 1232, 0x8000));

  auto malformed = makeQuery("example.com", 1);
  malformed[12] = 0xC0;
  assert(!parses(malformed, 1, "example.com"));

  malformed = makeQuery("example.com", 1);
  malformed[5] = 2;
  assert(!parses(malformed, 1, "example.com"));

  malformed = makeQuery("example.com", 1, true);
  malformed[malformed.size() - 1] = 4;
  malformed.insert(malformed.end(), {0, 8, 0, 4, 1});
  assert(!parses(malformed, 1, "example.com"));

  malformed = makeQuery("example.com", 1);
  malformed.push_back(0);
  assert(!parses(malformed, 1, "example.com"));

  malformed = makeQuery("example.com", 1);
  malformed[12] = 3;
  malformed[13] = '-';
  malformed[14] = 'x';
  malformed[15] = 'y';
  assert(!parses(malformed, 1, "example.com"));
}
