#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <vector>

#define TYPE_TCP 0x06
#define HTTP_PORT 0x50
#define HTTPS_PORT 0x1BB

struct ip_header{
    u_int8_t ver;
    u_int8_t size;
    u_int8_t type;
    u_int32_t src;
    u_int32_t dst;
};

struct tcp_header{
    u_int16_t src;
    u_int16_t dst;
    u_int8_t size;
};

struct http_header{
    std::vector<u_int8_t> host;
};

ip_header getIP(const u_char *packet){
    ip_header ip;

    // IP Version
    ip.ver = packet[0] >> 4;

    // IP Header Size
    ip.size = packet[0] & 0xf;

    // Protocol
    ip.type = packet[9];

    // Source IP
    ip.src += packet[12] << 24;
    ip.src += packet[13] << 16;
    ip.src += packet[14] << 8;
    ip.src += packet[15];

    // Destination IP
    ip.dst += packet[16] << 24;
    ip.dst += packet[17] << 16;
    ip.dst += packet[18] << 8;
    ip.dst += packet[19];

    return ip;
}

tcp_header getTCP(const u_char *packet, u_int8_t size){
    tcp_header tcp;

    // Source Port
    tcp.src = packet[size] << 8;
    tcp.src += packet[size+1];

    // Destination Port
    tcp.dst = packet[size+2] << 8;
    tcp.dst += packet[size+3];

    tcp.size = packet[size+12] >> 4;

    return tcp;
}

http_header getHTTP(const u_char *packet, u_int8_t size){
    http_header http;

    int i = size;
    while(true)
        if(packet[i++] == 0x0d) break;

    i+=7;

    while(true){
        if(packet[i] == 0x0d) break;
        http.host.push_back(packet[i++]);
    }

    return http;
}
