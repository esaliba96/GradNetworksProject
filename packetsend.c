#include "packetsend.h"

//builds the arp packet and ships out 
int send_arp_packet(struct ether_addr *src_mac, struct ether_addr *dest_mac, 
  in_addr_t dest_ip, in_addr_t src_ip){
  int sendlen;
  struct arp_packet packet;
  memset(&packet,0,64);
  struct sockaddr_ll sadr_ll;
  sadr_ll.sll_ifindex = ifreq_ip.ifr_ifindex; //interface index
	sadr_ll.sll_halen = ETH_ALEN; //length of mac address
  memcpy(&(sadr_ll.sll_addr),dest_mac,6);
  //build the arp packet for sending
  build_arp_packet(&packet, src_mac, dest_mac, dest_ip, src_ip);

  sendlen = sendto(sock_r, &packet, 64, 0,(const struct sockaddr*)&sadr_ll, 
    sizeof(struct sockaddr_ll));
}

void send_dns_response(char *query_packet, struct ether_addr *src_MAC,
  in_addr_t ip_addr)
{
  struct dns_packet_ptr resp_packet_ptr;

  int len = sizeof(struct eth_header) + 
    ((struct ip_header *)
    (query_packet + sizeof(struct eth_header)))->total_length;

  char *dns_query = query_packet + sizeof(struct eth_header) + 
    sizeof(struct ip_header) + sizeof(struct udp_header);
  unsigned dns_query_len = len - sizeof(struct ip_header) - 
    sizeof(struct udp_header);
  
  build_dns_response(&resp_packet_ptr, dns_query, dns_query_len, ip_addr);

  char *resp_packet = malloc(sizeof(struct eth_header) + 
    sizeof(struct ip_header) + sizeof(struct udp_header) + 
    resp_packet_ptr.len);
  
  struct eth_header *e_header = (struct eth_header *)resp_packet;
  memcpy(&(e_header->dest_MAC), 
    &(((struct eth_header *)query_packet)->src_MAC), 
    sizeof(struct ether_addr));
  memcpy(&e_header->src_MAC, src_MAC, sizeof(struct ether_addr));
  e_header->type = htons(IPV4_ETH_TYPE);

  struct ip_header *i_header = (struct ip_header *)((char *)e_header + 
    sizeof(struct eth_header));
  i_header->version_length = 0x45; //ipv4, no options present
  i_header->service_type = 0; //normal service
  i_header->total_length = htons(sizeof(struct ip_header) + 
    sizeof(struct udp_header) + resp_packet_ptr.len);
  i_header->identifier = 0;
  i_header->flags_offset = 0x4000; //do not fragment, first fragment
  i_header->time_live = 32; //arbitrary
  i_header->protocol = UDP_PROTO;
  i_header->src = 
    ((struct ip_header *)(query_packet + sizeof(struct eth_header)))->dest;
  i_header->dest = 
    ((struct ip_header *)(query_packet + sizeof(struct eth_header)))->src;
  i_header->checksum = htons(in_cksum((unsigned short *)i_header, 
    sizeof(struct ip_header)));  
  
  struct udp_header *u_header = 
    (struct udp_header *)((char *)i_header + sizeof(struct ip_header));
  u_header->src_port = htons(53);
  u_header->dest_port = htons(56266);
  u_header->len = htons(sizeof(struct udp_header) + resp_packet_ptr.len);
  u_header->checksum = htons(in_cksum((unsigned short *)u_header, 
    sizeof(struct udp_header) + resp_packet_ptr.len));
  
  memcpy((char *)u_header + sizeof(struct udp_header), 
    resp_packet_ptr.payload, resp_packet_ptr.len);

  unsigned resp_len = sizeof(struct eth_header) + sizeof(struct ip_header) + 
    sizeof(struct udp_header) + resp_packet_ptr.len;

  struct sockaddr_ll saddr_ll;
  saddr_ll.sll_ifindex = ifreq_ip.ifr_ifindex; //interface index
  saddr_ll.sll_halen = ETH_ALEN; //length of mac address
  memcpy(&(saddr_ll.sll_addr), 
    &(((struct eth_header *)query_packet)->src_MAC), 
    sizeof(struct ether_addr));

  int sendlen = sendto(sock_r, &resp_packet, resp_len, 0, 
    (const struct sockaddr *)&saddr_ll, sizeof(struct sockaddr_ll));

  if(sendlen < 0)
  {
    perror("sendto failue!");
    exit(EXIT_FAILURE);
  }
}

