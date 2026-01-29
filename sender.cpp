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
#include <mutex>
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

void send_worker(int thread_id, std::string dest_ip, int total_rate, int n_msg, std::string ciphertext_str) {
    uint16_t port = BASE_PORT + thread_id;

    // Crea un socket UDP
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Errore creazione socket su thread " << thread_id << std::endl;
        return;
    }

    sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(sockaddr_in));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    inet_pton(AF_INET, dest_ip.c_str(), &dest_addr.sin_addr);

    // Prealloco chunk da inviare
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

    // Calcolo intervallo per thread
    long interval_ns = (1000000000L * N_PORTS) / total_rate;
    
    auto next_send_time = std::chrono::high_resolution_clock::now();

    for (int i = 1 + thread_id; i <= n_msg; i += N_PORTS) {
        
        // Invia i chunk pre allocati
        for (uint32_t c = 0; c < num_chunks; c++) {
            // Aggiorna solo il message_id nel buffer già pronto
            TelemetryHeader* hdr_ptr = (TelemetryHeader*)packet_buffers[c].data();
            hdr_ptr->message_id = i;
            
            sendto(sock, packet_buffers[c].data(), packet_buffers[c].size(), 0,
                    (const sockaddr*)&dest_addr, sizeof(dest_addr));
        }

        if (i % 1000 == 1 + thread_id || i % 1000 == 0) { 
             if (i % 1000 == 0) {
                 std::cout << "[Thread " << thread_id << "] Inviato msg " << i << "/" << n_msg << " su porta " << port << std::endl;
             }
        }
        
        // Busy wait per inviare ad un certo rate (con sleep non era abbastanza preciso)
        next_send_time += std::chrono::nanoseconds(interval_ns);
        while (std::chrono::high_resolution_clock::now() < next_send_time) {}
    }

    close(sock);
}

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

    // Prepara buffer 
    std::stringstream ss;
    ctx.save(ss, seal::compr_mode_type::none);
    std::string ciphertext_str = ss.str();
    std::cout << "Ciphertext: " << ciphertext_str.size() << " bytes" << std::endl;

    std::cout << "Invio a " << dest_ip << " su porte " << BASE_PORT << "-" << (BASE_PORT + N_PORTS - 1) 
              << " con " << N_PORTS << " thread." << std::endl;

    std::vector<std::thread> threads;
    for (int i = 0; i < N_PORTS; i++) {
        threads.emplace_back(send_worker, i, dest_ip, rate, n_msg, ciphertext_str);
    }

    for (auto& t : threads) {
        t.join();
    }

    std::cout << "Fine invio di " << n_msg << " messaggi" << std::endl;
    return 0;
}
