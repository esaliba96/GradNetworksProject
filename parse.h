#ifndef PARSE_H
#define PARSE_H
#include "packetutil.h"

void print_ether(uint8_t *packet);
void print_arp(uint8_t *packet);
void packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet);

#endif
