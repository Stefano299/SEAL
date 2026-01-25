#include "message.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

// Costruttore con parametri
Message::Message(const std::string& data, uint32_t msg_id)
    : data(data), message_id(msg_id), sock(-1), socket_created(false) {
    memset(&dest_addr, 0, sizeof(dest_addr));
    // Buffer pre allocato per l'invio
    send_buffer.reserve(sizeof(TelemetryHeader) + CHUNK_SIZE);
}

// Distruttore
Message::~Message() {
    if (socket_created && sock >= 0) {
        close(sock);
    }
}

// Crea il socket UDP
bool Message::createSocket(const std::string& dest_ip, uint16_t port) {
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Errore creazione socket" << std::endl;
        return false;
    }
    
    // Configurazione indirizzo di destinazione
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, dest_ip.c_str(), &dest_addr.sin_addr) <= 0) {
        std::cerr << "Indirizzo IP non valido: " << dest_ip << std::endl;
        close(sock);
        sock = -1;
        return false;
    }
    
    socket_created = true;
    std::cout << "Socket creato con successo verso " << dest_ip << ":" << port << std::endl;
    return true;
}

// Usa un socket esistente
void Message::useSocket(int32_t existing_sock, const sockaddr_in& dest) {
    sock = existing_sock;
    dest_addr = dest;
    socket_created = false;  // Per non chiudere questo socket nel distruttore
}

// Invia il messaggio frammentato
int32_t Message::send() {
    if (sock < 0) {
        std::cerr << "Socket non inizializzato, chiama createSocket() prima" << std::endl;
        return -1;
    }
    
    uint32_t total_size = getTotalSize();
    uint32_t num_chunks = getNumChunks();
    
    //std::cout << "Invio messaggio ID " << message_id << ": " << total_size 
    //           << " bytes in " << num_chunks << " chunk" << std::endl;
    
    // std::vector<char> pkt;
    // pkt.reserve(sizeof(TelemetryHeader) + CHUNK_SIZE);
    
    for (uint32_t i = 0; i < num_chunks; i++) {
        // Calcolo offset e dimensione chunk
        uint32_t offset = i * CHUNK_SIZE;
        uint32_t remaining = total_size - offset;
        uint32_t chunk_size = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
        
        // Creazione header
        TelemetryHeader hdr;
        hdr.message_id = message_id;
        hdr.total_chunks = static_cast<uint16_t>(num_chunks);
        hdr.chunk_index = static_cast<uint16_t>(i);
        hdr.ciphertext_total_size = total_size;
        hdr.chunk_size = static_cast<uint16_t>(chunk_size);
        
        // Preparo buffer (ridimensiona solo se serve)
        send_buffer.resize(sizeof(TelemetryHeader) + chunk_size);
        
        memcpy(send_buffer.data(), &hdr, sizeof(TelemetryHeader));
        memcpy(send_buffer.data() + sizeof(TelemetryHeader), data.data() + offset, chunk_size);
        
        // Invio
        int32_t sent = sendto(sock, send_buffer.data(), send_buffer.size(), 0,
                              (const sockaddr*)&dest_addr, sizeof(dest_addr));
        
        if (sent < 0) {
            perror("sendto failed");
            return -1;
        }
        
        // std::cout << "  Chunk " << (i + 1) << "/" << num_chunks 
        //           << " inviato (" << sent << " bytes)" << std::endl;

    }
    
    // std::cout << "Invio del messaggio " << message_id << " completato" << std::endl;
    return static_cast<int32_t>(num_chunks);
}

void Message::closeSocket() {
    if (socket_created && sock >= 0) {
        close(sock);
        sock = -1;
        socket_created = false;
    }
}

void Message::setData(const std::string& d) {
    data = d;
}

void Message::setMessageId(uint32_t id) {
    message_id = id;
}

std::string Message::getData() const {
    return data;
}

uint32_t Message::getMessageId() const {
    return message_id;
}

uint32_t Message::getTotalSize() const {
    return static_cast<uint32_t>(data.size());
}

uint32_t Message::getNumChunks() const {
    uint32_t total = getTotalSize();
    return (total + CHUNK_SIZE - 1) / CHUNK_SIZE;
}

int32_t Message::getSocket() const {
    return sock;
}