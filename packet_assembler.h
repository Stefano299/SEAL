#ifndef PACKET_ASSEMBLER_H
#define PACKET_ASSEMBLER_H

#include "message.h"
#include <cstdint>
#include <vector>
#include <unordered_map>

// Classe per l'assemblaggio di chunk in un messaggio (in ricezione)
class PacketAssembler {
public:
  // Risultato dell'elaborazione di un pacchetto
  struct AssemblyResult {
    bool complete;
    uint32_t message_id;
    std::vector<char> data; // Se il messaggio è stato completato contiene i dati assemblati
  };

  // Struttura necessaria per tenere traccia di più pacchetti contemporaneamente
  struct MessageInfo {
    bool active = false;
    uint16_t total_chunks = 0;
    uint32_t size = 0;
    uint32_t received_count = 0;
    std::vector<char> data;
    std::vector<bool> chunk_received;
  };

  PacketAssembler() = default;

  // Processa un pacchetto ricevuto (buffer con header + payload)
  AssemblyResult process_packet(const char *packet, size_t packet_size);

  // Resetta lo stato per un determinato messaggio
  void reset(uint32_t message_id);

private:
  std::unordered_map<uint32_t, MessageInfo> messages;
};

#endif
