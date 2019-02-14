#include "packetsend.h"

//builds the arp packet and ships out 
int send_packet(struct ether_addr *src_mac, struct ether_addr *dest_mac, in_addr_t dest_ip, in_addr_t src_ip){
  int sendlen;
  struct arp_packet packet;
  memset(&packet,0,64);
  struct sockaddr_ll sadr_ll;
  sadr_ll.sll_ifindex = ifreq_ip.ifr_ifindex; //interface index
	sadr_ll.sll_halen = ETH_ALEN; //length of mac address
  memcpy(&(sadr_ll.sll_addr),dest_mac,6);
  //build the arp packet for sending
  build_arp_packet(&packet, src_mac, dest_mac, dest_ip, src_ip);

  sendlen = sendto(sock_r, &packet, 64, 0,(const struct sockaddr*)&sadr_ll, sizeof(struct sockaddr_ll));
}
