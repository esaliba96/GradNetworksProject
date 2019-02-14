#ifndef PACKET_SEND_H
#define PACKET_SEND_H
#include "packetutil.h"

int send_packet(uint8_t *src_mac, uint8_t *dest_mac, in_addr_t dest_ip, in_addr_t src_ip);

#endif
