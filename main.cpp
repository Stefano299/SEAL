#include <iostream>
#include <vector>
#include <cstring>
#include <thread>
#include <chrono>
#include <fstream>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "seal/seal.h"
#include "common.h"
#include "fhe_helpers.h"
#include "sender_utils.h"

using namespace seal;

int main(int argc, char* argv[]) {
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(2048);
    parms.set_coeff_modulus(CoeffModulus::Create(2048, {40}));
    parms.set_plain_modulus(65537);
    SEALContext context(parms);

    SecretKey secret_key;
    PublicKey public_key;

    //Generazione chiavi
    KeyGenerator keygen(context);
    secret_key = keygen.secret_key();
    keygen.create_public_key(public_key);
    
    if (argc < 4) {  //se = 1 allora crea chiavi
        std::cerr << "Argomenti necessari: IP destinazione, rate invio, n. messaggi da inviare" << std::endl;
        return 1;
    }
    
    std::string hop_node_ip = argv[1];
    int rate = std::atoi(argv[2]);
    int n_messages = std::atoi(argv[3]);
    

    Encryptor encryptor(context, public_key);
    BatchEncoder encoder(context);

    if (rate <= 0) {
        std::cerr << "Il rate deve essere > 0 " << std::endl;
        return 1;
    }
    
    int interval_ms = 1000 / rate;

    std::vector<uint64_t> initial_latency(encoder.slot_count(), 0ULL);
    Plaintext ptx;
    encoder.encode(initial_latency, ptx);
    Ciphertext ctx;
    encryptor.encrypt(ptx, ctx);

    std::stringstream ss;
    ctx.save(ss);
    std::string ciphertext_str = ss.str();

    //Dimensione del pacchetto senza header
    const uint32_t total_size = static_cast<uint32_t>(ciphertext_str.size());
    const size_t header_size = sizeof(TelemetryHeader);
    //Dimensione del pacchetto con header
    const size_t full_packet_size = header_size + total_size;

    std::cout << "Ciphertext generato: " << total_size << " bytes" << std::endl;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Errore creazione socket" << std::endl;
        return 1;
    }

    sockaddr_in hop_addr{};
    hop_addr.sin_family = AF_INET;
    hop_addr.sin_port = htons(UDP_PORT_BASE);
    if (inet_pton(AF_INET, hop_node_ip.c_str(), &hop_addr.sin_addr) <= 0) {
        std::cerr << "Indirizzo IP non valido: " << hop_node_ip << std::endl;
        close(sock);
        return 1;
    }

    std::cout << "Inizio invio a " << hop_node_ip << ":" << UDP_PORT_BASE
              << " ciphertext " << total_size << " con frammentazione" << std::endl;

    uint32_t message_id = 1;
    uint32_t i = 1;
    while (i <= n_messages) {
        send_ciphertext(sock, ciphertext_str, message_id, hop_addr, true);
        i++;
        message_id++;
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }

    close(sock);
    return 0;
}