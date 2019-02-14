#ifndef PACKET_UTIL_H
#define PACKET_UTIL_H

#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <sys/types.h>
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
  uint8_t sender_mac[6]; //Not in network order
  in_addr_t sender_ip; //
  uint8_t target_mac[6]; //*******
  in_addr_t target_ip;
}__attribute__((packed));

//28 + 14 + 22
struct arp_packet{
  struct eth_header ether_head;
  struct arp_header arp_head;
  char buffer[22];
}__attribute__((packed));

void build_arp_packet(struct arp_packet *packet, uint8_t *src, uint8_t *dest, in_addr_t dest_ip, in_addr_t src_ip);

struct ip_header {
  uint8_t version_length;
  uint8_t service_type;
  uint16_t total_length;
  uint16_t identifier;
  uint16_t flags_offset;
  uint8_t time_live;
  uint8_t protocol;
  uint16_t checksum;
  in_addr_t src;
  in_addr_t dest;
} __attribute__((packed));


struct udp_header {
  uint16_t src_port;
  uint16_t dest_port;
  uint16_t len;
  uint16_t checksum;
} __attribute__((packed));

int sock_r;
struct ifreq ifreq_ip;
  

#endif
