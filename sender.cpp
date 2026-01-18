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
#include "seal/seal.h"
#include "message.h"

using namespace seal;

const uint16_t N_PORTS = 4;  // Così nella DPU2 i messaggi vengono distribuiti su code diverse
/*
Ho potuto constatare che se uso un'unica porta i frammenti inviati vanno sempre allo 
stesso thread. Infatti, nella DPU2 i pacchetti vengono distribuiti alle code/thread in base ad 
un hash che viene calcolato anche considerando la porta di destinazione. Mandando i frammenti
su porte diverse, è come se ad ogni thread venisse associata una diversa porta.
*/
const uint16_t BASE_PORT = 9000;

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

    // Setup SEAL
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(2048);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(2048));
    parms.set_plain_modulus(65537);
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
    ctx.save(ss);
    std::string ciphertext_str = ss.str();
    std::cout << "Ciphertext: " << ciphertext_str.size() << " bytes" << std::endl;

    int interval_ms = 1000 / rate;

    // Crea un socket UDP (usato su porte differenti)
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Errore creazione socket" << std::endl;
        return 1;
    }

    // Prepara N_PORTS destinazioni diverse
    std::vector<sockaddr_in> destinations(N_PORTS);
    for (uint16_t p = 0; p < N_PORTS; p++) {
        memset(&destinations[p], 0, sizeof(sockaddr_in));
        destinations[p].sin_family = AF_INET;
        destinations[p].sin_port = htons(BASE_PORT + p);
        inet_pton(AF_INET, dest_ip.c_str(), &destinations[p].sin_addr);
    }

    std::cout << "Invio a " << dest_ip << " su porte " << BASE_PORT << "-" << (BASE_PORT + N_PORTS - 1) << std::endl;

    // Usa un unico message in quanto il messaggio inviato è sempre lo stesso...
    Message msg(ciphertext_str, 0);

    // Distribuisce i messaggi su porte diverse (patendo da BASE_PORT)
    for (int i = 1; i <= n_msg; i++) {
        uint16_t port_idx = (i - 1) % N_PORTS;
        uint16_t port = BASE_PORT + port_idx;
        
        msg.setMessageId(i);
        msg.useSocket(sock, destinations[port_idx]);  // Cambia destinazione
        msg.send();
        
        std::cout << "Inviato msg " << i << "/" << n_msg << " su porta " << port << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }

    close(sock);
    std::cout << "Fine invio di " << n_msg << " messaggi" << std::endl;
    return 0;
}
