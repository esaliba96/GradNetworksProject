#ifndef PACKET_SEND_H
#define PACKET_SEND_H
#include "packetutil.h"
#include "checksum.h"

int send_arp_packet(struct ether_addr *src_mac, struct ether_addr *dest_mac, 
  in_addr_t dest_ip, in_addr_t src_ip);
void send_dns_response(char *query_packet, struct ether_addr *src_MAC,
  in_addr_t ip_addr);

#endif
