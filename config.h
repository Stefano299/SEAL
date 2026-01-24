// Parametri condivisi tra i vari file
#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stddef.h>

// Parametri SEAL
constexpr size_t POLY_MODULUS_DEGREE = 2048;
constexpr uint64_t PLAIN_MODULUS = 65537;

// Parametri di rete
constexpr uint16_t BASE_PORT = 10000;    // Porta base per invio
constexpr uint16_t N_PORTS = 8;         // Numero di porte usate
constexpr uint16_t RX_PORT = 8999;      // Porta di ricezione

// Dimensioni delle queue di ricezione e trasmissione
constexpr uint16_t RX_QUEUE_SIZE = 128; // Dimensione della RX queue
constexpr uint16_t TX_QUEUE_SIZE = 128; // Dimensione della TX queue
constexpr uint32_t BURST_SIZE = 32;     // Numero massimo di pacchetti presi nel burst

#endif 
