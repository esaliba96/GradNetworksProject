#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>

/* max length of a dot-notation ip address including null terminator */
#define MAX_IP_LEN 16

int main(int argc, char *argv[]) {
  pcap_t *handle;
  char *dev;
  char err_buf[PCAP_ERRBUF_SIZE];
  char filter_exp[20]; /* size needed to store "net " and an ip addr */
  struct bpf_program fp;
  bpf_u_int32 netmask;
  bpf_u_int32 ip;

  /* Find our network interface device */
  dev = pcap_lookupdev(err_buf);
  if(!dev) {
    fprintf(stderr, "Couldn't find default device: %s\n", err_buf);
    exit(EXIT_FAILURE);
  }

  /* Find our ip and netmask */
  if (pcap_lookupnet(dev, &ip, &netmask, err_buf) == -1) {
    fprintf(stderr, "Couldn't get ip and netmask for device %s: %s\n", dev, err_buf);
	  ip = 0;
		netmask = 0;
	}

  /* Open the session in promiscuous mode */
  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, err_buf);
  if(!handle) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, err_buf);
    exit(EXIT_FAILURE);
  }

  strcpy(filter_exp, "net ");
  strncpy(filter_exp + strlen("net "), argv[1], MAX_IP_LEN);

  if(pcap_compile(handle, &fp, filter_exp, 0, ip)) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
	  exit(EXIT_FAILURE);
	}

	if(pcap_setfilter(handle, &fp)) {
	  fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

  /* session should be ready to go once we have a callback function to service packets
    we can call pcap_loop() here */
}
