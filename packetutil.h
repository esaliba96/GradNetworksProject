#ifndef PACKET_UTIL_H
#define PACKET_UTIL_H

#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
//#include <netinet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>

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
  uint16_t hardware_type; //Not in network order
  uint16_t protocol_type; //Not in network order
  uint8_t hardware_size; // Not in network order
  uint8_t protocol_size; // Not in network order
  uint16_t op; //Not in network order
  struct ether_addr sender_mac; //Not in network order
  struct in_addr sender_ip; //
  struct ether_addr target_mac; //*******
  struct in_addr target_ip;
}__attribute__((packed));

//28 + 14 + 22
struct arp_packet{
  struct eth_header ether_head;
  struct arp_header arp_head;
  char buffer[22];
}__attribute__((packed));

void build_arp_packet(struct arp_packet *packet, uint8_t *src, uint8_t *dest, struct in_addr dest_ip, struct in_addr src_ip);

int sock_r;
struct ifreq ifreq_ip;
  

#endif
