#ifndef COMMON_H
#define COMMON_H

#include <cstdint>

constexpr uint16_t CHUNK_SIZE = 10000;
constexpr uint16_t UDP_PORT_BASE = 9000;
constexpr uint16_t NUM_PORTS = 19;

#pragma pack(push, 1)
struct TelemetryHeader {
  uint32_t message_id;
  uint16_t total_chunks;
  uint16_t chunk_index;
  uint32_t ciphertext_total_size;
  uint16_t chunk_size;
};
#pragma pack(pop)

#endif
