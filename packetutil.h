#ifndef PACKET_UTIL_H
#define PACKET_UTIL_H

#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
//#include <netinet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>


//ethernet_header_size: 14 bytes
struct eth_header{
  uint8_t dest_MAC[6];
  uint8_t src_MAC[6]; 
  uint16_t type;
}__attribute__((packed));

//ether_addr is 48 bits --> 6 bytes(MAC)
//in_addr is 32 bits --> 4 bytes(IP)
//Total Arp_Header_Size: 28 bytes
struct arp_header{
  uint16_t hardware_type;
  uint16_t protocol_type;
  uint8_t hardware_size;
  uint8_t protocol_size;
  uint16_t op;
//  struct ether_addr sender_mac;
//  struct in_addr sender_ip;
//  struct ether_addr target_mac;
//  struct in_addr target_ip;
}__attribute__((packed));

struct arp_packet{
  struct eth_header eth_head;
  struct arp_header arp_head;
  char buffer[18];
  char crc[4];
}__attribute__((packed));

void build_arp_packet(struct arp_packet *packet, struct ether_addr src, struct ether_addr dest, char *data );


#endif
