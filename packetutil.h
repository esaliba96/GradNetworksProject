#ifndef PACKET_UTIL_H
#define PACKET_UTIL_H

#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/in.h>

//ethernet_header_size: 14 bytes
struct ethernet_header{
  struct ether_addr dest;
  struct ether_addr host;
  uint16_t type;
}__attribute__((packed));

//ether_addr is 48 bits --> 6 bytes(MAC)
//in_addr is 32 bits --> 4 bytes(IP)
//Total Arp_Header_Size: 28 bytes
struct arp_header{
  uint16_t hardware;
  uint16_t protocol_type;
  uint8_t hardware_size;
  uint8_t protocol_size;
  uint16_t opcode;
  struct ether_addr sender_mac;
  struct in_addr sender_ip;
  struct ether_addr target_mac;
  struct in_addr target_ip;
}__attribute__((packed));

struct arp_packet{
  struct ethernet_header eth_head;
  struct arp_header arp_head;
  char buffer[18];
  char crc[4];
}__attribute__((packed));

void build_arp_packet(struct arp_packet *packet, struct ether_addr src, struct ether_addr dest, char *data );


#endif
