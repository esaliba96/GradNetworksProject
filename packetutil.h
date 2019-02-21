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

void build_arp_packet(struct arp_packet *packet, uint8_t *src, uint8_t *dest, struct in_addr dest_ip, struct in_addr src_ip);
void build_dns_response(struct dns_packet_ptr *resp_ptr, 
  struct dns_packet_ptr *query_pointer);

#endif
