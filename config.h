// Parametri condivisi tra i vari file
#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stddef.h>

// Parametri SEAL
constexpr size_t POLY_MODULUS_DEGREE = 2048;
constexpr uint64_t PLAIN_MODULUS = 65537;

// Parametri di rete
constexpr uint16_t BASE_PORT = 9000;    // Porta base per invio
constexpr uint16_t N_PORTS = 4;         // Numero di porte usate
constexpr uint16_t RX_PORT = 8999;      // Porta di ricezione

#endif 
