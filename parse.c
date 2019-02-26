#include "packetsend.h"
#include "parse.h"
#include <sys/types.h>
#include <sys/socket.h>

void packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, 
  const u_char *packet) {
    print_ether((uint8_t*)packet);
    return;
}

void print_ether(uint8_t *packet) {
  char *dest, *src;
  uint8_t *data;

  struct eth_header *eth = (struct eth_header*)packet;

  printf("\tEthernet Header\n");
      
  dest = ether_ntoa(&eth->dest_MAC  );
  printf("\t\tDest MAC: %s\n", dest);

  src = ether_ntoa(&eth->src_MAC  );
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
    
    struct ip_header *i_header = (struct ip_header *)(packet + 
      sizeof(struct eth_header));
    
    if(i_header->protocol == UDP_PROTO)
    {
      struct udp_header *u_header = (struct udp_header *)(((char *)i_header) +
        ntohs(i_header->total_length));

      if(ntohs(u_header->dest_port) == 53)
      {
        int len = i_header->total_length - sizeof(struct ip_header) + 
          sizeof(struct udp_header);

        send_dns_response(packet, len, &global_mac, &(eth->src_MAC), 
          i_header->dest, i_header->src);
      }
    }
        
  } else {
    printf("Unknown\n\n");
  }
}

void print_arp(uint8_t *packet) {
  uint8_t *sender_MAC, *target_MAC;
  in_addr_t *sender_IP, *target_IP;

  struct arp_header *arp = (struct arp_header*)(packet);

  printf("\tARP header\n");
  printf("\t\tOpcode: ");
  arp->op = ntohs(arp->op);
  if (arp->op == 1) {
    printf("Request\n");
    send_arp_packet(&global_mac, &(arp->sender_mac), htonl(arp->sender_ip),
      htonl(arp->target_ip));
  } else if (arp->op == 2) {
    printf("Reply\n");
  } else {
    printf("Unknown\n");
  }
   
  struct in_addr sender;
  sender.s_addr = arp->sender_ip;
  struct in_addr dest;
  dest.s_addr = arp->target_ip;
  printf("\t\tSender MAC: %s\n", ether_ntoa(&(arp->sender_mac)));
  printf("\t\tSender IP: %s\n", inet_ntoa(sender));
  printf("\t\tTarget MAC: %s\n", ether_ntoa(&(arp->dest_mac)));
  printf("\t\tTarget IP: %s\n\n", inet_ntoa(dest));
}

void print_IP(uint8_t *packet) {
  char *protocol_name = NULL;
  struct ip_header *ip = (struct ip_header*)(packet);
  int checksum;
  struct in_addr net;
  uint8_t* data;

  switch (ip->protocol) {
    case 0x11:
      protocol_name = "UDP";
      break;
    default:
      protocol_name = "Unknown"; 
  }

  net.s_addr = ip->src;
  printf("\t\tSender IP: %s\n", inet_ntoa(net));
  net.s_addr = ip->dest;
  printf("\t\tDest IP: %s\n", inet_ntoa(net));

  data = packet + ((ip->version_length & 0x0F) * 4);
  switch (ip->protocol) {
    case 0x11:
      print_UDP(data);
      break;
    default:
      printf("%d\n", ip->protocol);
      break;
  }
}

void print_UDP(uint8_t *packet) {
  struct udp_header *udp = (struct udp_header*)(packet);
  int src_port = (int)ntohs(udp->src_port);
  int dest_port = (int)ntohs(udp->dest_port);
  printf("\n\tUDP Header\n");

  printf("\t\tSource Port:  ");
  TCP_UDP_port_print(src_port);   
}

void TCP_UDP_port_print(int port) {
  switch(port) {
    case 53:
      printf("DNS");
      break;
    default:
      printf("%d", port);
      break;
  }
  printf("\n\n");
}


