// Receiver, da eseguire in nsp1

#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include "seal/seal.h"
#include "packet_assembler.h"
#include "config.h"

using namespace seal;

int main() {
    // Setup SEAL con parametri da config.h
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(POLY_MODULUS_DEGREE);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(POLY_MODULUS_DEGREE));
    parms.set_plain_modulus(PLAIN_MODULUS);
    SEALContext context(parms);

    // Carica secret key da file
    SecretKey secret_key;
    std::ifstream sk_file("secret.key", std::ios::binary);
    if (!sk_file) {
        std::cerr << "secret.key non trovata" << std::endl;
        return 1;
    }
    secret_key.load(context, sk_file);
    sk_file.close();
    std::cout << "Secret key caricata" << std::endl;

    Decryptor decryptor(context, secret_key);
    BatchEncoder encoder(context);
    
    PacketAssembler assembler;

    // Socket UDP
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Errore socket" << std::endl;
        return 1;
    }
    
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(RX_PORT);
    
    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Errore bind porta " << RX_PORT << std::endl;
        close(sock);
        return 1;
    }
    
    // Aumenta buffer di ricezione 
    int recv_buf_size = 8 * 1024 * 1024;  // 8 MB
    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &recv_buf_size, sizeof(recv_buf_size)) < 0) {
        std::cerr << "Warning: impossibile aumentare buffer ricezione" << std::endl;
    }
    
    std::cout << "In ascolto su porta " << RX_PORT << std::endl;
    
    std::vector<char> buffer(sizeof(TelemetryHeader) + CHUNK_SIZE);

    while (true) {
        sockaddr_in sender;
        socklen_t sender_len = sizeof(sender);
        
        ssize_t n = recvfrom(sock, buffer.data(), buffer.size(), 0,
                             (sockaddr*)&sender, &sender_len);
        
        if (n > 0) {
            // std::cout << "Ricevuti " << n << " bytes" << std::endl; // Commentato per prestazioni

            auto result = assembler.process_packet(buffer.data(), n);
            
            if (result.complete) {
                std::cout << "Messaggio " << result.message_id << " completo (" 
                     << result.data.size() << " bytes)" << std::endl;
                
                // Decripta
                std::stringstream ss(std::string(result.data.begin(), result.data.end()));
                Ciphertext ct;
                ct.load(context, ss);

                Plaintext ptx;
                decryptor.decrypt(ct, ptx);

                std::vector<uint64_t> valori;
                encoder.decode(ptx, valori);

                std::cout << "Valore decriptato: " << valori[0]
                     << ", atteso: 13291" << std::endl;
            }
        }
    }
    
    close(sock);
    return 0;
}