#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>


void print_as_bytes(unsigned char *buff, ssize_t length) {
  for (ssize_t i = 0; i < length; i++, buff++)
    printf("%.2x ", *buff);
}

u_int16_t compute_icmp_checksum(const void *buff, int length) {
  u_int32_t sum;
  const u_int16_t *ptr = buff;
  assert(length % 2 == 0);
  for (sum = 0; length > 0; length -= 2)
    sum += *ptr++;
  sum = (sum >> 16) + (sum & 0xffff);
  return (u_int16_t)(~(sum + (sum >> 16)));
}

//create and config header
struct icmp icmp_header(int ttl) {
  struct icmp header;
  header.icmp_type = ICMP_ECHO;
  header.icmp_code = 0;
  header.icmp_hun.ih_idseq.icd_id = (uint16_t)getpid();
  header.icmp_hun.ih_idseq.icd_seq = htons(ttl);
  header.icmp_cksum = 0;
  header.icmp_cksum = compute_icmp_checksum((u_int16_t *)&header, sizeof(header));

  return header;
}
//send 3 packages with given ttl
void send_packages(struct timespec *start, int sockfd, struct sockaddr_in addr, int ttl) {
  struct icmp header = icmp_header(ttl);
  setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));

  size_t bytes_sent;
  timespec_get(start, TIME_UTC);
  for (int i = 0; i < 3; i++)
    if ((bytes_sent = sendto(sockfd, &header, sizeof(header), 0, (struct sockaddr *)&addr, sizeof(addr))) == -1) {
      fprintf(stderr, "sendto error: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }
}

// check if package is response to one we send from current round
int check_package(uint8_t *buffer, int ttl) {
  struct ip *ip_header = (struct ip *)buffer;
  ssize_t offset = 4 * ip_header->ip_hl;

  u_int8_t *icmp_packet = buffer + offset;
  
  struct icmp *icmp_header = (struct icmp *)icmp_packet;

  if (icmp_header->icmp_type == ICMP_TIME_EXCEEDED) {
  
    offset += 8;
    ip_header = (struct ip *)(buffer+offset);
    offset += 4 * ip_header->ip_hl;
  
  }
  
  icmp_packet = buffer + offset;
  icmp_header = (struct icmp *)(icmp_packet);

  uint16_t id = icmp_header->icmp_id;
  uint16_t seq = ntohs(icmp_header->icmp_seq);
	
  return (id == (uint16_t)getpid() && seq == ttl) ? 1 : 0;
}

//print response for given round
void printf_received_from(char senders_string_addr[3][20], uint64_t times[3], int count, int ttl) {
  // check if senders are equal
  if (count == 0){
    printf("%d.\t", ttl);
    printf("*\n");
  }
  else if (count == 3 && !strcmp(senders_string_addr[0], senders_string_addr[1]) && !strcmp(senders_string_addr[1], senders_string_addr[2])){
    printf("%d.\t", ttl);
    printf("%s\t\t%ld ms\n", senders_string_addr[0], (times[0] + times[1] + times[2]) / 3);
}
  else if (count == 2 && !strcmp(senders_string_addr[0], senders_string_addr[1])){
    printf("%d.\t", ttl);
    printf("%s\t\t??? ms\n", senders_string_addr[0]);
  }
  else
    for (int i = 0; i < count; i++){
      printf("%d.\t", ttl);
      printf("%s\t\t???\n", senders_string_addr[i]);
    }
}

uint64_t measure_time(struct timespec *start, struct timespec *end) {
  return (uint64_t)(end->tv_sec * 1000 + end->tv_nsec / 1000000) - (uint64_t)(start->tv_sec * 1000 + start->tv_nsec / 1000000);
}

//nonblocking receive packages
int receive_packages(struct timespec *start, int sock_descr, char *address, int64_t ttl) {
  struct timespec end;
  char senders_ip_str[3][20];
  uint64_t times[3];
  struct sockaddr_in sender;
  socklen_t sender_len = sizeof(sender);
  u_int8_t buffer[IP_MAXPACKET];

  fd_set descriptors;
  FD_ZERO(&descriptors);
  FD_SET(sock_descr, &descriptors);
  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  int ready;

  int count = 0;
  ssize_t packet_len;
  while(count < 3){

    ready = select(sock_descr + 1, &descriptors, NULL, NULL, &tv); 
    if(ready < 0)
    	exit(0);
    if(ready ==0)
	    break;
    packet_len = recvfrom(sock_descr, buffer, IP_MAXPACKET, MSG_DONTWAIT, (struct sockaddr *)&sender, &sender_len);

    // save time of receiving
    timespec_get(&end, TIME_UTC);

    if (packet_len < 0) {
      fprintf(stderr, "recvfrom error: %s\n", strerror(errno));
      return EXIT_FAILURE;
    }

    // check if package has ours ttl and pid if so store info about it
    if (check_package(buffer, ttl)) {
      inet_ntop(AF_INET, &(sender.sin_addr), senders_ip_str[count], sizeof(senders_ip_str[count]));
      times[count] = measure_time(start, &end);
      count++;
    }
  }

  printf_received_from(senders_ip_str, times, count, ttl);
  if (!strcmp(senders_ip_str[count - 1], address))
    return 1;
  else
    return 0;
}

struct sockaddr_in set_address(char *address) {
  struct sockaddr_in recipient;
  bzero(&recipient, sizeof(recipient));
  recipient.sin_family = AF_INET;

  if (!inet_pton(AF_INET, address, &recipient.sin_addr)) {
    fprintf(stderr, "inet error: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }
  return recipient;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "minimalistic traceroute implementation.\nUsage: pass valid ipv4 address as argument to program \nExample: ./traceroute 8.8.8.1\n");
    return EXIT_FAILURE;
  }

  if (geteuid() != 0) {
    fprintf(stderr, "Program needs superuser privileges to work properly.\n");
    return EXIT_FAILURE;
  }

  char *address = argv[1];
  struct sockaddr_in addr = set_address(address);

  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sockfd < 0) {
    fprintf(stderr, "socket error: %s\n", strerror(errno));
    return EXIT_FAILURE;
  }

  struct timespec time_start;

  //main loop
  for (int ttl = 1; ttl <= 30; ttl++) {
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));

    send_packages(&time_start, sockfd, addr, ttl);
    
    //if we received response from address we wanted to trace we can break from the loop and return
    if (receive_packages(&time_start, sockfd, address, ttl) == 1)
      break;
  }

  return EXIT_SUCCESS;
}
