//File packetutil.c
//Desc: Contains functions for packet manipulation and packet definition. Currently, only contains definitions for arp packets. 

#include "packetutil.h"

/**********************************************************************************************
  Func Name: build_arp_packet
  Argument Def:
    packet: inner packet components
    src: source mac address
    dest: destination mac address
  Func Def:
    Builds an arp_reply packet including CRC
**********************************************************************************************/
void build_arp_packet(struct arp_packet *packet, struct ether_addr src, struct ether_addr dest){

}
