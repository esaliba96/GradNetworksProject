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
void build_arp_packet(struct arp_packet *packet, struct ether_addr *src, struct ether_addr *dest, in_addr_t dest_ip, in_addr_t src_ip){
  //build eth frame
  struct eth_header e_header;
  memcpy(&(e_header.dest_MAC), dest, 6);
  memcpy(&(e_header.src_MAC), src, 6);
  e_header.type = htons(0x0806);

  //build arp frame 
  struct arp_header a_header;
  a_header.hardware_type = htons(0x0001);
  a_header.protocol_type = htons(0x0800);
  a_header.hardware_size = 0x06;
  a_header.protocol_size = 0x04;
  a_header.op = htons(0x0002);
  memcpy(&(a_header.sender_mac), src,6);
  a_header.sender_ip = htonl(src_ip);
  memcpy(&(a_header.dest_mac), dest,6);
  a_header.target_ip = htonl(dest_ip);

  memcpy(&(packet->ether_head), &e_header, 14);
  memcpy(&(packet->arp_head), &a_header, 28);
  memset(&(packet->buffer), 0, 18); 
  // printf("%.4x\n",a_header.hardware_type);
  // printf("%.4x\n",a_header.protocol_type);
}
