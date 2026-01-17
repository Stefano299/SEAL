#ifndef PACKET_ASSEMBLER_H
#define PACKET_ASSEMBLER_H

#include "message.h"
#include <cstdint>
#include <vector>

// Classe per l'assemblaggio di chunk in un messaggio (in ricezione)
class PacketAssembler {
public:
  // Risultato dell'elaborazione di un pacchetto
  struct AssemblyResult {
    bool complete;
    uint32_t message_id;
    std::vector<char> data; // I dati dopo che è stato completato
  };

  PacketAssembler()
      : active(false), message_id(0), total_chunks(0), size(0),
        received_count(0) {}
  // Processa un pacchetto ricevuto (buffer con header + payload)
  AssemblyResult process_packet(const char *packet, size_t packet_size);

  // Resetta lo stato dell'assemblatore
  void reset();

  bool is_active() const { return active; }
  uint32_t current_message_id() const { return message_id; }
  uint32_t get_received_count() const { return received_count; }
  uint16_t get_total_chunks() const { return total_chunks; }

private:
  bool active;
  uint32_t message_id;
  uint16_t total_chunks;
  uint32_t size;
  uint32_t received_count;
  std::vector<char> data;
  std::vector<bool> chunk_received;
};

#endif
