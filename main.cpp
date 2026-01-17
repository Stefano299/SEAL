#include <iostream>
#include <vector>
#include <cstring>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include "seal/seal.h"
#include "message.h"

using namespace seal;

int main(int argc, char* argv[]) {
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(2048);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(2048));
    parms.set_plain_modulus(65537);
    SEALContext context(parms);

    SecretKey secret_key;
    PublicKey public_key;

    // Generazione chiavi
    KeyGenerator keygen(context);
    secret_key = keygen.secret_key();
    keygen.create_public_key(public_key);
    
    if (argc < 4) {
        std::cerr << "Argomenti necessari: IP destinazione, rate invio, n. messaggi da inviare" << std::endl;
        return 1;
    }
    
    std::string hop_node_ip = argv[1];
    uint32_t rate = static_cast<uint32_t>(std::atoi(argv[2]));
    uint32_t n_messages = static_cast<uint32_t>(std::atoi(argv[3]));

    Encryptor encryptor(context, public_key);
    BatchEncoder encoder(context);

    if (rate <= 0) {
        std::cerr << "Il rate deve essere > 0 " << std::endl;
        return 1;
    }
    
    uint32_t interval_ms = 1000 / rate;

    std::vector<uint64_t> initial_latency(encoder.slot_count(), 0ULL);
    Plaintext ptx;
    encoder.encode(initial_latency, ptx);
    Ciphertext ctx;
    encryptor.encrypt(ptx, ctx);

    std::stringstream ss;
    ctx.save(ss);
    std::string ciphertext_str = ss.str();

    std::cout << "Ciphertext generato: " << ciphertext_str.size() << " bytes" << std::endl;

    // Porta UDP destinazione
    const uint16_t port = 9000;

    // Creazione messaggio con socket incapsulato
    Message msg(ciphertext_str, 1);
    if (!msg.createSocket(hop_node_ip, port)) {
        std::cerr << "Errore creazione socket" << std::endl;
        return 1;
    }

    std::cout << "Inizio invio a " << hop_node_ip << ":" << port
              << " ciphertext di " << ciphertext_str.size() << " bytes, con frammentazione" << std::endl;

    // Invio messaggi
    for (uint32_t msg_id = 1; msg_id <= static_cast<uint32_t>(n_messages); msg_id++) {
        msg.setMessageId(msg_id);
        msg.send();
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }

    // Il socket viene chiuso automaticamente dal distruttore
    return 0;
}