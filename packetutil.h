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

#define MAX_DNS_NAME_LEN 255
#define IPV4_ETH_TYPE 0x0800
#define UDP_PROTO 17 
#define DNS_STANDARD_QUERY 0x0100

//ethernet_header_size: 14 bytes
struct eth_header{
  struct ether_addr dest_MAC;
  struct ether_addr src_MAC; 
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
  in_addr_t sender_ip; //
  struct ether_addr dest_mac; //*******
  in_addr_t target_ip;
}__attribute__((packed));

//28 + 14 + 22
struct arp_packet{
  struct eth_header ether_head;
  struct arp_header arp_head;
  char buffer[22];
}__attribute__((packed));

struct dns_header{
  uint16_t message_id;
  uint16_t flags;
  uint16_t total_questions;
  uint16_t total_answer_rr;
  uint16_t total_authority_rr;
  uint16_t total_additional_rr;
}__attribute__((packed));

/* static fields of a dns question */
struct dns_question_fields{
  uint16_t type;
  uint16_t class;
}__attribute__((packed));

/* static fields of a dns answer */
struct dns_answer_fields{
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t data_len; /* always 4 for us */
  /* technically variable length, but we're only sending ipv4 addrs */
  in_addr_t data;
}__attribute__((packed));

/* Necessary as DNS payloads are variable length */
struct dns_packet_ptr{
  void *payload;
  unsigned len;
};

void build_dns_response(struct dns_packet_ptr *resp_ptr, 
  char *dns_query, int len, in_addr_t ip_addr);
void build_arp_packet(struct arp_packet *packet, struct ether_addr *src, 
  struct ether_addr *dest, in_addr_t dest_ip, in_addr_t src_ip);

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
struct ether_addr global_mac;  
struct in_addr global_ip;

#endif
