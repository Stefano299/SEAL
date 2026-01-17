#ifndef SENDER_UTILS_H
#define SENDER_UTILS_H

#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <vector>

#include "common.h"


//Ritorna il numero di chunk inviati, -1 se errore
int32_t send_ciphertext(int32_t sock, std::string data, uint32_t msg_id, 
                        sockaddr_in dest, bool print_debug)
{
    uint32_t total_size = data.size();
    uint32_t num_chunks = (total_size + CHUNK_SIZE - 1) / CHUNK_SIZE; //Arrotonda per eccesso

    for (uint32_t i = 0; i < num_chunks; i++)
    {
        // calcolo offset e dimensione chunk
        uint32_t offset = i * CHUNK_SIZE;
        uint32_t remaining = total_size - offset;
        uint32_t chunk_size = remaining < CHUNK_SIZE ? remaining : CHUNK_SIZE;

        //Headerdel pacchetto inviato
        TelemetryHeader hdr;
        hdr.message_id = msg_id;
        hdr.total_chunks = num_chunks;
        hdr.chunk_index = i;
        hdr.ciphertext_total_size = total_size;
        hdr.chunk_size = chunk_size;

        //Creazione pacchetto 
        std::vector<char> pkt(sizeof(TelemetryHeader) + chunk_size); 
        memcpy(pkt.data(), &hdr, sizeof(TelemetryHeader));
        memcpy(pkt.data() + sizeof(TelemetryHeader), data.data() + offset, chunk_size);

        //Invio
        int32_t sent = sendto(sock, pkt.data(), pkt.size(), 0,
                              (sockaddr*)&dest, sizeof(dest));
        
        if (sent < 0)
        {
            perror("sendto failed");
            return -1;
        }

        if (print_debug)
        {
            std::cout << "Messaggio " << msg_id << " chunk " << (i + 1) << "/" << num_chunks
                      << " inviato " << sent << " bytes" << std::endl;
        }
    }

    return num_chunks;
}

#endif
