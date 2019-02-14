#ifndef PACKET_SEND_H
#define PACKET_SEND_H
#include "packetutil.h"

int send_packet(struct ether_addr *src_mac, struct ether_addr *dest_mac, in_addr_t dest_ip, in_addr_t src_ip);

#endif
