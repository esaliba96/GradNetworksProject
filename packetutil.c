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

static unsigned calc_dns_name_len(char* name){
  unsigned len = 1;
  unsigned num_following_chars = *name;

  while(num_following_chars && len <= MAX_DNS_NAME_LEN)
  {
    len = len + num_following_chars + 1;
    name = name + num_following_chars + 1;
    num_following_chars = *name;
  }

  if(len > MAX_DNS_NAME_LEN)
  {
    fprintf(stderr, "DNS name exceeded maximum length!\n");
    exit(EXIT_FAILURE);
  }

  return len;
}

void build_dns_response(struct dns_packet_ptr *resp_ptr, 
  char *dns_query, int len, in_addr_t ip_addr){

  struct dns_header *query_header = (struct dns_header *)(dns_query);
  unsigned name_field_len = calc_dns_name_len((char *)(dns_query + 
    sizeof(struct dns_header)));

  printf("name_field_len: %u\n", name_field_len);
  /* calculate length of response packet */
  size_t resp_len = sizeof(struct dns_header) + name_field_len * 2 + 
    sizeof(struct dns_question_fields) + sizeof(struct dns_answer_fields);

  struct dns_header *resp_header = malloc(resp_len);
  resp_header->message_id = query_header->message_id;
  resp_header->flags = htons(ntohs(query_header->flags) | 0x8000);
  resp_header->total_questions = htons(1);
  resp_header->total_answer_rr = htons(1);
  resp_header->total_authority_rr = 0;
  resp_header->total_additional_rr = 0;
  
  memcpy(((char *)resp_header) + sizeof(struct dns_header), 
    ((char *)query_header) + sizeof(struct dns_header), name_field_len + 
    sizeof(struct dns_question_fields));

  char *answer_name_field = ((char *)(resp_header) + 
    sizeof(struct dns_header) + name_field_len + 
    sizeof(struct dns_question_fields));

  memcpy(answer_name_field, ((char *)query_header) + sizeof(struct dns_header), 
    name_field_len);

  struct dns_answer_fields *answer_fields = 
    (struct dns_answer_fields *)(answer_name_field + name_field_len);
  
  answer_fields->type = htons(1);
  answer_fields->class = htons(1);
  answer_fields->ttl = htonl(60);
  answer_fields->data_len = htons(4);
  answer_fields->data = global_ip.s_addr;

  resp_ptr->payload = resp_header;
  resp_ptr->len = resp_len;
}

