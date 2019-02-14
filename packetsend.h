#ifndef PACKET_SEND_H
#define PACKET_SEND_H
#include "packetutil.h"

int send_packet(uint8_t *src_mac, uint8_t *dest_mac, struct in_addr dest_ip, struct in_addr src_ip);

#endif
