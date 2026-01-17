#include <cstring>
#include <iostream>

#include "packet_assembler.h"

PacketAssembler::AssemblyResult
PacketAssembler::process_packet(const char *packet, size_t packet_size) {
  AssemblyResult result{false, 0, {}};

  if (packet_size < sizeof(TelemetryHeader))
    return result;

  TelemetryHeader hdr;
  memcpy(&hdr, packet, sizeof(TelemetryHeader));

  // Reset se non attivo o se arriva un nuovo messaggio
  if (!active || hdr.message_id != message_id) {
    active = true;
    message_id = hdr.message_id;
    total_chunks = hdr.total_chunks;
    size = hdr.ciphertext_total_size;
    received_count = 0;
    data.assign(size, 0);
    chunk_received.assign(total_chunks, false);
  }

  // Calcola posizione e dimensione
  size_t pos = hdr.chunk_index * CHUNK_SIZE;
  size_t dim = hdr.chunk_size;

  // Controlla se proverebbe a scrivere oltre il buffer
  if (pos + dim > data.size()) {
    std::cerr << "Errore: tentativo di scrivere oltre il buffer" << std::endl;
    dim = data.size() - pos;
  }

  // Copia solo se chunk non è già stato ricevuto
  if (!chunk_received[hdr.chunk_index]) {
    memcpy(data.data() + pos, packet + sizeof(TelemetryHeader), dim);
    chunk_received[hdr.chunk_index] = true;
    received_count++;
  }

  // Verifica completamento
  if (received_count == total_chunks) {
    result.complete = true;
    result.message_id = message_id;
    result.data = std::move(data);
    reset();
  }

  return result;
}

void PacketAssembler::reset() {
  active = false;
  message_id = 0;
  total_chunks = 0;
  size = 0;
  received_count = 0;
  data.clear();
  chunk_received.clear();
}
