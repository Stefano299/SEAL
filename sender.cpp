// Sender, da eseguire in nsp0

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <chrono>
#include <thread>
#include "seal/seal.h"
#include "message.h"
#include "config.h"

using namespace seal;

/*
Ho potuto constatare che se uso un'unica porta i frammenti inviati vanno sempre allo 
stesso thread. Infatti, nella DPU2 i pacchetti vengono distribuiti alle code/thread in base ad 
un hash che viene calcolato anche considerando la porta di destinazione. Mandando i frammenti
su porte diverse, è come se ad ogni thread venisse associata una diversa porta.
*/

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Argomenti non validi: <IP_destinazione> <rate> <n_messaggi>" << std::endl;
        return 1;
    }
    
    std::string dest_ip = argv[1];
    int rate = atoi(argv[2]);
    int n_msg = atoi(argv[3]);
    
    if (rate <= 0) {
        std::cerr << "Il rate deve essere > 0" << std::endl;
        return 1;
    }

    // Setup SEAL con parametri da config.h
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(POLY_MODULUS_DEGREE);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(POLY_MODULUS_DEGREE));
    parms.set_plain_modulus(PLAIN_MODULUS);
    SEALContext context(parms);

    // Carica public key da file
    PublicKey public_key;
    std::ifstream pk_file("public.key", std::ios::binary);
    if (!pk_file) {
        std::cerr << "public.key non trovata" << std::endl;
        return 1;
    }
    public_key.load(context, pk_file);
    pk_file.close();
    std::cout << "Chiave pubblica caricata" << std::endl;

    Encryptor encryptor(context, public_key);
    BatchEncoder encoder(context);

    // Crea un ciphertext con tutti gli elementi uguali a 0
    std::vector<uint64_t> valori(encoder.slot_count(), 0ULL);
    Plaintext ptx;
    encoder.encode(valori, ptx);
    Ciphertext ctx;
    encryptor.encrypt(ptx, ctx);

    // Prepara buffer (senza compressione per velocizzare load sulla DPU)
    std::stringstream ss;
    ctx.save(ss, seal::compr_mode_type::none);
    std::string ciphertext_str = ss.str();
    std::cout << "Ciphertext: " << ciphertext_str.size() << " bytes" << std::endl;

    int interval_us = 1000000 / rate;
    
    // Crea un socket UDP (usato su porte differenti)
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Errore creazione socket" << std::endl;
        return 1;
    }

    // Prepara invio su N_PORTS porte diverse
    std::vector<sockaddr_in> destinations(N_PORTS);
    for (uint16_t p = 0; p < N_PORTS; p++) {
        memset(&destinations[p], 0, sizeof(sockaddr_in));
        destinations[p].sin_family = AF_INET;
        destinations[p].sin_port = htons(BASE_PORT + p);
        inet_pton(AF_INET, dest_ip.c_str(), &destinations[p].sin_addr);
    }

    std::cout << "Invio a " << dest_ip << " su porte " << BASE_PORT << "-" << (BASE_PORT + N_PORTS - 1) << std::endl;

    // Prealloco chunk da inviare, per rendere il send più veloce
    uint32_t total_size = ciphertext_str.size();
    uint32_t num_chunks = (total_size + CHUNK_SIZE - 1) / CHUNK_SIZE;
    
    // Vettore di buffer pre allocati
    std::vector<std::vector<char>> packet_buffers(num_chunks);
    
    for (uint32_t i = 0; i < num_chunks; i++) {
        uint32_t offset = i * CHUNK_SIZE;
        uint32_t remaining = total_size - offset;
        uint32_t chunk_size = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
        
        // Preparo header
        TelemetryHeader hdr;
        hdr.message_id = 0; 
        hdr.total_chunks = (uint16_t)num_chunks;
        hdr.chunk_index = (uint16_t)i;
        hdr.ciphertext_total_size = total_size;
        hdr.chunk_size = (uint16_t)chunk_size;
        
        packet_buffers[i].resize(sizeof(TelemetryHeader) + chunk_size);
        
        // Copia header
        memcpy(packet_buffers[i].data(), &hdr, sizeof(TelemetryHeader));
        
        // Copia il buffer del ciphertext
        memcpy(packet_buffers[i].data() + sizeof(TelemetryHeader), 
               ciphertext_str.data() + offset, chunk_size);
    }

    std::cout << "Pre allocati " << num_chunks << " pacchetti" << std::endl;

    long interval_ns = 1000000000L / rate;
    
    // Timer usato per inviare ad un particolare rate
    auto next_send_time = std::chrono::high_resolution_clock::now();

    // Distribuisce i messaggi su porte diverse (patendo da BASE_PORT)
    for (int i = 1; i <= n_msg; i++) {
        uint16_t port_idx = (i - 1) % N_PORTS;
        const sockaddr_in& dest = destinations[port_idx];
        
        // Invia i chunk pre allocati
        for (uint32_t c = 0; c < num_chunks; c++) {
            // Aggiorna solo il message_id nel buffer già pronto
            TelemetryHeader* hdr_ptr = (TelemetryHeader*)packet_buffers[c].data();
            hdr_ptr->message_id = i;
            
            sendto(sock, packet_buffers[c].data(), packet_buffers[c].size(), 0,
                    (const sockaddr*)&dest, sizeof(dest));
        }

        if (i % 1000 == 0) { 
            std::cout << "Inviato msg " << i << "/" << n_msg << " su porta " << (BASE_PORT + port_idx) << std::endl;
        }
        
        // Busy wait per inviare ad un certo rate
        next_send_time += std::chrono::nanoseconds(interval_ns);
        while (std::chrono::high_resolution_clock::now() < next_send_time) {}
    }

    close(sock);
    std::cout << "Fine invio di " << n_msg << " messaggi" << std::endl;
    return 0;
}
