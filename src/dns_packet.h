#pragma once

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>

static inline size_t parseDnsQuery(const uint8_t* pkt, int len, char* out,
                                   uint16_t* qtype, int* qend, bool* hasEdns,
                                   uint16_t* udpPayload, uint16_t* ednsFlags,
                                   uint16_t maxUdpPayload) {
  if (!pkt || !out || !qtype || !qend || !hasEdns || !udpPayload || !ednsFlags ||
      len < 17 || (pkt[2] & 0x80) || (pkt[2] & 0x78) ||
      (pkt[3] & 0x40) || pkt[4] != 0 || pkt[5] != 1 ||
      pkt[6] || pkt[7] || pkt[8] || pkt[9] || pkt[10] || pkt[11] > 1)
    return 0;

  *hasEdns = false;
  *udpPayload = 512;
  *ednsFlags = 0;
  int i = 12;
  size_t o = 0;
  bool terminated = false;
  while (i < len) {
    uint8_t labelLength = pkt[i++];
    if (labelLength == 0) {
      terminated = true;
      break;
    }
    if ((labelLength & 0xC0) || labelLength > 63 ||
        o + labelLength + (o ? 1 : 0) > 253 || i + labelLength > len)
      return 0;
    if (o) out[o++] = '.';
    for (uint8_t k = 0; k < labelLength; k++) {
      unsigned char ch = pkt[i++];
      if (!(std::isalnum(ch) || ch == '-' || ch == '_') ||
          (k == 0 && ch == '-') || (k == labelLength - 1 && ch == '-'))
        return 0;
      out[o++] = (char)std::tolower(ch);
    }
  }
  if (!terminated || o == 0) return 0;
  out[o] = 0;
  if (i + 4 > len) return 0;
  *qtype = ((uint16_t)pkt[i] << 8) | pkt[i + 1];
  if (pkt[i + 2] != 0 || pkt[i + 3] != 1) return 0;
  *qend = i + 4;
  i = *qend;

  if (pkt[11] == 0) {
    if (i != len) return 0;
  } else {
    if (i + 11 > len || pkt[i] != 0 || pkt[i + 1] != 0 ||
        pkt[i + 2] != 41 || pkt[i + 5] != 0 || pkt[i + 6] != 0 ||
        ((((uint16_t)pkt[i + 7] << 8) | pkt[i + 8]) & 0x7FFF))
      return 0;
    uint16_t rdlength = ((uint16_t)pkt[i + 9] << 8) | pkt[i + 10];
    if (i + 11 + rdlength != len) return 0;
    int option = i + 11;
    while (option < len) {
      if (option + 4 > len) return 0;
      uint16_t optionLength = ((uint16_t)pkt[option + 2] << 8) | pkt[option + 3];
      option += 4;
      if (option + optionLength > len) return 0;
      option += optionLength;
    }
    *hasEdns = true;
    *udpPayload = ((uint16_t)pkt[i + 3] << 8) | pkt[i + 4];
    if (*udpPayload < 512) *udpPayload = 512;
    if (*udpPayload > maxUdpPayload) *udpPayload = maxUdpPayload;
    *ednsFlags = (((uint16_t)pkt[i + 7] << 8) | pkt[i + 8]) & 0x8000;
  }

  if (o > 4 && std::strncmp(out, "www.", 4) == 0) {
    std::memmove(out, out + 4, o - 3);
    o -= 4;
  }
  return o;
}
