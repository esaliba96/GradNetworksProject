#include "parse.h"
#include "packetutil.h"
#include <stdlib.h>
#include <string.h>
 
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
  char buffer[20];

  if (argc != 3) {
    fprintf(stderr, "usage: exec <target_ip> <interface_name> \n");
    exit(EXIT_FAILURE);
  } else {
    sprintf(buffer, "net %s", argv[1]); 
  }

  /* Find our network interface device */
  dev = pcap_lookupdev(err_buf);
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
 
  /* Open the session in promiscuous mode */
  handle = pcap_open_live(argv[2], BUFSIZ, 1, 1000, err_buf);
  if(!handle) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, err_buf);
    exit(EXIT_FAILURE);
  }

  if(pcap_compile(handle, &fp, NULL, 0, ip)) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
	  exit(EXIT_FAILURE);
	}

	if(pcap_setfilter(handle, &fp)) {
	  fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

  sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if(sock_r < 0){
    printf("Failure to open socket\n");
    exit(EXIT_FAILURE);
  }
  memset(&ifreq_ip, 0, sizeof(ifreq_ip));
  strncpy(ifreq_ip.ifr_name, argv[2], IFNAMSIZ-1);
  
  if((ioctl(sock_r, SIOCGIFINDEX, &ifreq_ip))<0){
    printf("error in SIOCGIFINDEX \n");
  }

  if((ioctl(sock_r, SIOCGIFHWADDR, &ifreq_ip))<0){
    printf("error in SIOCGIFHWADDR ioctl reading\n");
  }
  memcpy(&global_mac,&(ifreq_ip.ifr_hwaddr.sa_data),6);
   
  if(ioctl(sock_r,SIOCGIFADDR,&ifreq_ip)<0){
    printf("error in SIOCGIFADDR \n");
  }
    
  inet_aton(argv[1], &global_ip);

  pcap_loop(handle, 0, packet_handler, NULL);
}
