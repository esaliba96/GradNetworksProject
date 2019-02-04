#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include "parse.h"
#include <sys/socket.h>
#include <netinet/in.h>

/* max length of a dot-notation ip address including null terminator */
#define MAX_IP_LEN 16

int main(int argc, char *argv[]) {
  pcap_t *handle;
  char *dev;
  char err_buf[PCAP_ERRBUF_SIZE];
  char filter_exp[20];  //size needed to store "net " and an ip addr 
  struct bpf_program fp;
  bpf_u_int32 netmask;
  bpf_u_int32 ip;
  const u_char *packet;
  struct pcap_pkthdr header;
  int sock_r;
  

  /* Find our network interface device */
  dev = pcap_lookupdev(err_buf);
  printf("%s\n",dev);
  if(!dev) {
    fprintf(stderr, "Couldn't find default device: %s\n", err_buf);
    exit(EXIT_FAILURE);
  }

  /* Find our ip and netmask */
  if (pcap_lookupnet("lo", &ip, &netmask, err_buf) == -1) {
    fprintf(stderr, "Couldn't get ip and netmask for device %s: %s\n", dev, err_buf);
	  ip = 0;
		netmask = 0;
	}
  printf("%d\n",ip);
  printf("%d\n",netmask);

  /* Open the session in promiscuous mode */
  handle = pcap_open_live("wlp7s0", BUFSIZ, 1, 1000, err_buf);
  if(!handle) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, err_buf);
    exit(EXIT_FAILURE);
  }

  //strcpy(filter_exp, "net ");
//  strncpy(filter_exp + strlen("net "), argv[1], MAX_IP_LEN);

  if(pcap_compile(handle, &fp, "net 192.168.1.131", 0, ip)) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
	  exit(EXIT_FAILURE);
	}

	if(pcap_setfilter(handle, &fp)) {
	  fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

  sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL);
  if(sock_r < 0){
    printf("Failure to open socket\n");
    exit(EXIT_FAILURE);
  }

 // packet = pcap_next(handle, &header);
 // printf("%d",header.len);
  pcap_loop(handle, 10, packet_handler, NULL);
  /* session should be ready to go once we have a callback function to service packets
    we can call pcap_loop() here */
}
