#pragma once
#include <seal/seal.h>
#include <fstream>
#include <sstream>

// Funzione per salvare un oggetto SEAL su file
template <typename T>
void save_to_file(const T& obj, const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    obj.save(file);
    file.close();
}

// Funzione per caricare un oggetto SEAL da file
template <typename T>
void load_from_file(seal::SEALContext context, T& obj, const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    obj.load(context, file);
    file.close();
}