#ifndef MESSAGE_H
#define MESSAGE_H

#include <string>
#include <vector>
#include <cstdint>
#include <netinet/in.h>

const uint16_t CHUNK_SIZE = 1000; //Non conta l'header

//Header di ogni pacchetto. #pragma pack necessario per evitare padding
#pragma pack(push, 1)
struct TelemetryHeader {
    uint32_t message_id;            
    uint16_t total_chunks;          
    uint16_t chunk_index;           
    uint32_t ciphertext_total_size; 
    uint16_t chunk_size;            
};                                  // Totale di 14 bytes
#pragma pack(pop)

class Message {
private:
    std::string data;           // Dati del messaggio (ciphertext)
    uint32_t message_id;        // ID del messaggio
    int32_t sock;               // Socket UDP
    sockaddr_in dest_addr;      // Indirizzo destinazione
    bool socket_created;        // Flag per sapere se il socket è stato creato internamente
    std::vector<char> send_buffer; // Buffer per l'invio


public:
    Message(const std::string& data, uint32_t msg_id);
    // Distruttore per chiudere il socker
    ~Message();

    int32_t getSocket() const;
    // Crea socket interno che verrà usato per inviare il messaggio
    bool createSocket(const std::string& dest_ip, uint16_t port);
    // Usa un socket già esistente
    void useSocket(int32_t existing_sock, const sockaddr_in& dest);
    void closeSocket();
    // Invia il messaggio frammentato tramite socket
    // Ritorna il numero di chunk inviati, -1 se errore
    int32_t send();  

    void setData(const std::string& data);
    void setMessageId(uint32_t id);
    
    std::string getData() const;
    uint32_t getMessageId() const;
    uint32_t getTotalSize() const;
    uint32_t getNumChunks() const;  
};

#endif
