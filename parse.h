#ifndef PARSE_H
#define PARSE_H
#include "packetutil.h"

int sock_r;
struct ifreq ifreq_ip;

void print_ether(uint8_t *packet);
void print_arp(uint8_t *packet);
void packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet);
void print_UDP(uint8_t *packet);
void TCP_UDP_port_print(int port);
void print_IP(uint8_t *packet);

#endif
