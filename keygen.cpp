// Genera chiavi SEAL e le salva su file, da eseguire prima di receiver e sender

#include <iostream>
#include <fstream>
#include "seal/seal.h"
#include "config.h"

using namespace seal;
using namespace std;


int main() {
    // Parametri da config.h
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(POLY_MODULUS_DEGREE);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(POLY_MODULUS_DEGREE));
    parms.set_plain_modulus(PLAIN_MODULUS);
    
    SEALContext context(parms);
    
    // Genera le chiavi
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    // Salva secret key
    ofstream sk_file("secret.key", ios::binary);
    secret_key.save(sk_file);
    sk_file.close();
    cout << "Salvata secret.key" << endl;
    
    // Salva public key
    ofstream pk_file("public.key", ios::binary);
    public_key.save(pk_file);
    pk_file.close();
    cout << "Salvata public.key" << endl;
        
    return 0;
}
