#include <iostream>
#include <vector>
#include <cstring>
#include <thread>
#include <chrono>
#include <sstream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include "seal/seal.h"
#include "message.h"
#include "packet_assembler.h"

using namespace seal;

// Porta su cui ascolta il thread receiver
const uint16_t RECEIVE_PORT = 9001;

// Thread per la ricezione e riassemblaggio dei pacchetti
// Riceve puntatori al contesto SEAL per poter decriptare
void receiver_thread(SEALContext* context, Decryptor* decryptor, BatchEncoder* encoder) {
    PacketAssembler assembler;
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "[RECEIVER] Errore creazione socket" << std::endl;
        return;
    }
    
    sockaddr_in rx_addr{};
    rx_addr.sin_family = AF_INET;
    rx_addr.sin_addr.s_addr = INADDR_ANY;
    rx_addr.sin_port = htons(RECEIVE_PORT);
    
    if (bind(sock, (sockaddr*)&rx_addr, sizeof(rx_addr)) < 0) {
        std::cerr << "[RECEIVER] Errore bind sulla porta " << RECEIVE_PORT << std::endl;
        close(sock);
        return;
    }
    
    std::cout << "[RECEIVER] In ascolto sulla porta " << RECEIVE_PORT << std::endl;
    
    std::vector<char> buffer(sizeof(TelemetryHeader) + CHUNK_SIZE);
    
    while (true) {
        sockaddr_in sender_addr;
        socklen_t sender_len = sizeof(sender_addr);
        
        ssize_t received = recvfrom(sock, buffer.data(), buffer.size(), 0,
                                     (sockaddr*)&sender_addr, &sender_len);
        
        if (received > 0) {
            std::cout << "[RECEIVER] Ricevuto pacchetto di " << received << " bytes" << std::endl;
            
            auto result = assembler.process_packet(buffer.data(), received);
            
            if (result.complete) {
                std::cout << "[RECEIVER] Messaggio " << result.message_id 
                          << " riassemblato (" << result.data.size() << " bytes)" << std::endl;
                
                // Deserializza il ciphertext ricevuto
                std::stringstream ss(std::string(result.data.begin(), result.data.end()));
                Ciphertext received_ct;
                received_ct.load(*context, ss);

                Plaintext decrypted_ptx;
                decryptor->decrypt(received_ct, decrypted_ptx);

                std::vector<uint64_t> values;
                encoder->decode(decrypted_ptx, values);

                std::cout << "[RECEIVER] Messaggio decriptato: " << values[0] << std::endl;
            }
        }
    }
    
    close(sock);
}

int main(int argc, char* argv[]) {
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(2048);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(2048));
    parms.set_plain_modulus(65537);
    SEALContext context(parms);

    SecretKey secret_key;
    PublicKey public_key;

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
    Decryptor decryptor(context, secret_key);  // Per decriptare i messaggi ricevuti
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

    const uint16_t port = 9000;

    // Avvio thread di ricezione con contesto SEAL per decriptazione
    std::thread rx_thread(receiver_thread, &context, &decryptor, &encoder);

    // Invio messaggi (codice originale)
    Message msg(ciphertext_str, 1);
    if (!msg.createSocket(hop_node_ip, port)) {
        std::cerr << "Errore creazione socket" << std::endl;
        return 1;
    }

    std::cout << "Inizio invio a " << hop_node_ip << ":" << port
              << " ciphertext di " << ciphertext_str.size() << " bytes, con frammentazione" << std::endl;

    for (uint32_t msg_id = 1; msg_id <= n_messages; msg_id++) {
        msg.setMessageId(msg_id);
        msg.send();
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }

    std::cout << "Invio completato" << std::endl;
    
    // Attende il thread di ricezione (all'infinito)
    rx_thread.join();

    return 0;
}