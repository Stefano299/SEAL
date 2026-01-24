#include <cstring>
#include <iostream>

#include "packet_assembler.h"

PacketAssembler::AssemblyResult
// Ogni chiamata non alloca nuova memoria: assign non alloca nuova memoria se ne ha già abbastanza
// dopo che è stato fatto il clear nel metodo reset() (che non dealloca)
PacketAssembler::process_packet(const char *packet, size_t packet_size) {
  AssemblyResult result{false, 0, {}};

  if (packet_size < sizeof(TelemetryHeader))
    return result;

  TelemetryHeader hdr;
  memcpy(&hdr, packet, sizeof(TelemetryHeader));

  // NOTA se messages[hdr.message_id] non esiste, viene creato automaticamente
  MessageInfo& msg = messages[hdr.message_id];
  
  // In caso il messaggio non era ancora mai arrivato
  if (!msg.active) {
    msg.active = true;
    msg.total_chunks = hdr.total_chunks;
    msg.size = hdr.ciphertext_total_size;
    msg.received_count = 0;
    msg.data.assign(msg.size, 0);
    msg.chunk_received.assign(msg.total_chunks, false);
  }

  // Calcola posizione e dimensione
  size_t pos = hdr.chunk_index * CHUNK_SIZE;
  size_t dim = hdr.chunk_size;

  // Controlla se proverebbe a scrivere oltre il buffer
  if (pos + dim > msg.data.size()) {
    std::cerr << "Errore: tentativo di scrivere oltre il buffer" << std::endl;
    dim = msg.data.size() - pos;
  }

  // Copia solo se chunk non è già stato ricevuto
  if (!msg.chunk_received[hdr.chunk_index]) {
    memcpy(msg.data.data() + pos, packet + sizeof(TelemetryHeader), dim);
    msg.chunk_received[hdr.chunk_index] = true;
    msg.received_count++;
  }

  // Verifica completamento
  if (msg.received_count == msg.total_chunks) {
    result.complete = true;
    result.message_id = hdr.message_id;
    result.data = std::move(msg.data);
    reset(hdr.message_id);
  }

  return result;
}

void PacketAssembler::reset(uint32_t message_id) {
  messages.erase(message_id);  
}
