#include "packetutil.h"
#include "parse.h"

void packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet) {
    print_ether(packet);
    return;
}

void print_ether(const u_char *packet) {
  char *dest, *src;
  uint8_t *data;

  struct eth_header *eth = (struct eth_header*)packet;

  printf("\tEthernet Header\n");
      
  dest = ether_ntoa((struct ether_addr *)eth->dest_MAC  );
  printf("\t\tDest MAC: %s\n", dest);

  src = ether_ntoa((struct ether_addr *)eth->src_MAC  );
  printf("\t\tSource MAC: %s\n", src);

  eth->type = ntohs(eth->type);

  data = packet + sizeof(struct eth_header);

  printf("\t\tType: ");
  if (eth->type == 0x0806) {
     printf("ARP\n\n"); 
     print_arp(data);     
  } else if (eth->type == 0x0800) {
     printf("IP\n\n");
     print_IP(data);
  } else {
     printf("Unknown\n\n");
  }
}

void print_arp(uint8_t *packet) {
  uint8_t *sender_MAC, *target_MAC;
  in_addr_t *sender_IP, *target_IP;
  struct in_addr net;

  struct arp_header *arp = (struct arp_header*)(packet);

  printf("\tARP header\n");
  printf("\t\tOpcode: ");
  arp->op = ntohs(arp->op);
  if (arp->op == 1) {
     printf("Request\n");
  } else if (arp->op == 2) {
     printf("Reply\n");
  } else {
     printf("Unknown\n");
  }
   
  sender_MAC = (uint8_t *)arp + sizeof(struct arp_header);
  printf("\t\tSender MAC: %s\n", ether_ntoa((struct ether_addr *)sender_MAC));

  sender_IP = (in_addr_t *)(sender_MAC + arp->hardware_size);
  net.s_addr = (in_addr_t)*sender_IP;
  printf("\t\tSender IP: %s\n", inet_ntoa(net));

  target_MAC = (uint8_t*)sender_IP + arp->protocol_size;
  printf("\t\tTarget MAC: %s\n", ether_ntoa((struct ether_addr *)target_MAC));

  target_IP = (in_addr_t *)(target_MAC + arp->hardware_size);
  net.s_addr = (in_addr_t)*target_IP;
  printf("\t\tTarget IP: %s\n\n", inet_ntoa(net));
}
