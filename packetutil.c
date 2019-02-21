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
void build_arp_packet(struct arp_packet *packet, uint8_t *src, uint8_t *dest, struct in_addr dest_ip, struct in_addr src_ip){
  //build eth frame
  struct eth_header e_header;
  memcpy(&e_header.dest_MAC, dest, 6)
  memcpy(&e_header.src_MAC, src, 6);
  e_header.type = htons(0x0806);

  //build arp frame 
  struct arp_header a_header;
  a_header.hardware_type = htons(0x0001);
  a_header.protocol_type = htons(0x0800);
  a_header.hardware_size = 0x06;
  a_header.protocol_size = 0x04;
  a_header.op = htons(0x0002);
  a_header.sender_mac = src;
  a_header.sender_ip = htonl(src_ip);
  a_header.sender_mac = dest;
  a_header.sender_ip = htonl(dest_ip);

  memset(&packet.eth_header, &e_header, 14);
  memset(&packet.arp_header, &a_header, 28);
  memset(&packet.buffer, 0, 18); 
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

  if(len > MAX_DNS_LEN)
  {
    fprintf(stderr, "DNS name exceeded maximum length!\n");
    exit(EXIT_FAILURE);
  }

  return len;
}

void build_dns_response(struct dns_packet_ptr *resp_ptr, 
  struct dns_packet_ptr *query_ptr, in_addr ip_addr){

  struct dns_packet_ptr ret_struct;
  struct dns_header *query_header = (struct dns_header *)(query_ptr->payload);
  unsigned name_field_len = calc_dns_name_len((char *)(query_ptr->payload + 
    sizeof(dns_header)));
  /* calculate length of response packet */
  size_t resp_len = sizeof(dns_header) + name_field_len * 2 + 
    sizeof(dns_question_fields) + sizeof(dns_answer_fields);

  struct dns_header *resp_header = malloc(resp_len);
  resp_header->message_id = query_header->message_id;
  resp_header->flags = query_header->flags | 0x8000;
  resp_header->total_questions = 1;
  resp_header->total_answer_rr = 1;
  resp_header->total_authority_rr = 0;
  resp_header->total_additional_rr = 0;
  
  memcpy(resp_header + sizeof(dns_header), query_header + sizeof(dns_header), 
    name_field_len + sizeof(dns_question_fields));

  char *answer_name_field = ((char *)(resp_header) + 
    sizeof(dns_header) + name_field_len + sizeof(dns_question_fields));

  memcpy(answer_name_field, (char *)query_header + sizeof(dns_header), 
    name_field_len);

  struct dns_answer_fields *answer_fields = 
    (struct dns_answer_fields *)(answer_name_field + name_field_len);
  
  answer_fields->type = 1;
  answer_fields->class = 1;
  answer_fields->ttl = 300; 
  answer_fields->data_len = 4;
  answer_fields->data = ip_addr;
}

int main(void){
  struct arp_packet packet;
  build_arp_packet(&packet);
  return;
}
