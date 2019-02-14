#ifndef PACKET_SEND_H
#define PACKET_SEND_H
#include "packetutil.h"

int send_packet(int *socket,uint8_t *src, uint8_t *dest, struct in_addr dest_ip, struct in_addr src_ip);

#endif
