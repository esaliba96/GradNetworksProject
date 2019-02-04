#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>

/* max length of a dot-notation ip address including null terminator */
#define MAX_IP_LEN 16

int main(int argc, char *argv[]) {
  //pcap_t *handle;
   //char *dev;
  char err_buf[PCAP_ERRBUF_SIZE];
  //char filter_exp[20]; /* size needed to store "net " and an ip addr */
//  struct bpf_program fp;
  //bpf_u_int32 netmask;
  //bpf_u_int32 ip;
  pcap_if_t *alldevs, *d;


  /* Find our network interface device */
  //dev = pcap_lookupdev(err_buf);

  int i=0;
  int r = pcap_findalldevs(&alldevs, err_buf);
  printf("%d\n", r);  
/* Print the list */
        for(d=alldevs; d; d=d->next)
        {
            printf("%d. %s\n", ++i, d->name);
            // if (d->description)
            //     printf(" (%s)\n", d->description);
            // else
            //     printf(" (No description available)\n");
        }


  /* session should be ready to go once we have a callback function to service packets
    we can call pcap_loop() here */
   return 0;
}
