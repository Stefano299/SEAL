// Sender, da eseguire in nsp0

#include <sys/socket.h>
#include <unistd.h>
#include "seal/seal.h"
#include "message.h"

using namespace seal;

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

    // Invia
    const uint16_t port = 9000;
    int interval_ms = 1000 / rate;

    Message msg(ciphertext_str, 1);
    if (!msg.createSocket(dest_ip, port)) {
        std::cerr << "Errore socket" << std::endl;
        return 1;
    }

    std::cout << "Invio a " << dest_ip << ":" << port << std::endl;

    for (int i = 1; i <= n_msg; i++) {
        msg.setMessageId(i);
        msg.send();
        std::cout << "Inviato " << i << "/" << n_msg << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }

    std::cout << "Fine invio di " << n_msg << " messaggi" << std::endl;
    return 0;
}
