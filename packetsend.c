#include "packetsend.h"

//builds the arp packet and ships out 
int send_packet(uint8_t *src_mac, uint8_t *dest_mac, struct in_addr dest_ip, struct in_addr src_ip){
  int sendlen;
  struct arp_packet packet;
  struct sockaddr_ll sadr_ll;
  sadr_ll.sll_ifindex = config.ifr_ifindex; //interface index
	sadr_ll.sll_halen = ETH_ALEN; //length of mac address
  sadr_ll.sll_addr[0] = dest_mac[0];
  sadr_ll.sll_addr[1] = dest_mac[1];
  sadr_ll.sll_addr[2] = dest_mac[2];
  sadr_ll.sll_addr[3] = dest_mac[3];
  sadr_ll.sll_addr[4] = dest_mac[4];
  sadr_ll.sll_addr[5] = dest_mac[5];
  //build the arp packet for sending
  build_arp_packet(&packet, src_mac, dest_mac, dest_ip, src_ip);

  sendlen = sendto(socket)
}