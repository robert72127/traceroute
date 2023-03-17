#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>

void print_as_bytes (unsigned char* buff, ssize_t length)
{
	for (ssize_t i = 0; i < length; i++, buff++)
		printf ("%.2x ", *buff);	
}

u_int16_t compute_icmp_checksum (const void *buff, int length)
{
	u_int32_t sum;
	const u_int16_t* ptr = buff;
	assert (length % 2 == 0);
	for (sum = 0; length > 0; length -= 2)
		sum += *ptr++;
	sum = (sum >> 16) + (sum & 0xffff);
	return (u_int16_t)(~(sum + (sum >> 16)));
}

struct icmp icmp_header( int ttl){
		struct icmp header;
		header.icmp_type = ICMP_ECHO;
		header.icmp_code = 0;
		header.icmp_hun.ih_idseq.icd_id = getpid();
		header.icmp_hun.ih_idseq.icd_seq = ttl;
		header.icmp_cksum = 0;
		header.icmp_cksum = compute_icmp_checksum ( (u_int16_t*)&header, sizeof(header));
	return header;
}

void send_packages(struct timespec *start,int sockfd, struct sockaddr_in addr, int ttl){
	struct icmp header = icmp_header(ttl);
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));
	
        size_t bytes_sent;
		timespec_get(start, TIME_UTC);
        for(int i = 0; i < 3; i++)
		    if ( (bytes_sent = sendto(sockfd, &header, sizeof(header), 0, (struct sockaddr*)&addr, sizeof(addr))) == -1) 
                { // handle error 
				}
}

int check_package(uint8_t *buffer, int pid, int ttl){
		struct ip* ip_header = (struct ip*) buffer;
        ssize_t	ip_header_len = 4 * ip_header->ip_hl;
		

		u_int8_t* icmp_packet = buffer + ip_header_len;
			
		struct icmp* icmp_header = (struct icmp*) icmp_packet;

		//equivalent type to u_char
		uint8_t type = icmp_header->icmp_type;
		ssize_t offset = ip_header_len;

		if (type == ICMP_TIME_EXCEEDED){
			offset  += ICMP_MINLEN;
			offset  += 4 * ((struct ip *)(buffer + offset))->ip_hl;
		}
			
		struct icmp* icmp_offset = (struct icmp*)(buffer+offset);

		uint16_t ip = icmp_offset->icmp_id;
		uint16_t seq = icmp_offset->icmp_seq;

	return (ip == pid && seq == ttl)? 1 : 0;
}

void printf_received_from(char senders_string_addr[3][20], int times[3], int count, int ttl){
	printf("%d.\t",ttl);
	// check if senders are equal
	if (count == 0)
		printf("*\n");
	else if(count == 3 && !strcmp(senders_string_addr[0], senders_string_addr[1]) && !strcmp(senders_string_addr[1], senders_string_addr[2]))
		printf("%s\t\t%d ms\n", senders_string_addr[0], (times[0]+times[1]+times[2])/3 );	

	else if(count == 2 && !strcmp(senders_string_addr[0], senders_string_addr[1]))
		printf("%s\t\t??? ms\n", senders_string_addr[0]);	
	else
		for(int i = 0; i < count; i++)
			printf("%s\t\t???\n", senders_string_addr[i]);	
}

int64_t measure_time(struct timespec *start, struct timespec *end){
	int64_t time_start = (int)( start->tv_nsec / 1000000);
	int64_t time_end =   (int)(end->tv_nsec / 1000000);
	return (time_end-time_start);
}

int receive_packages(struct timespec *start, int sock_descr, char *address, int ttl){
	struct timespec end;

	char senders_ip_str[3][20];
	int times[3];
    struct sockaddr_in sender;	
	socklen_t sender_len = sizeof(sender);
	u_int8_t buffer[IP_MAXPACKET];

	fd_set descriptors;
	FD_ZERO (&descriptors);
	FD_SET (sock_descr, &descriptors);
	struct timeval tv; 
	tv.tv_sec = 1; 
	tv.tv_usec = 0;
	int ready; 
    
    int count = 0;
    ssize_t packet_len;	
	while (ready = select(sock_descr+1, &descriptors, NULL, NULL, &tv) & count < 3 ){
		packet_len = recvfrom (sock_descr, buffer, IP_MAXPACKET,  MSG_DONTWAIT,(struct sockaddr*)&sender, &sender_len); 
		timespec_get(&end, TIME_UTC);           
        if (packet_len < 0) {
			fprintf(stderr, "recvfrom error: %s\n", strerror(errno)); 
			return EXIT_FAILURE;
		}
            
		if(check_package(buffer, getpid(), ttl)){
 		   	//char sender_ip_str[count][20]; // moze miec inna wielkosc
			inet_ntop(AF_INET, &(sender.sin_addr), senders_ip_str[count], sizeof(senders_ip_str[count]));   
			times[count] = measure_time(start, &end); 
			count++;
		}
	}

		printf_received_from(senders_ip_str, times, count, ttl);
		if (! strcmp(senders_ip_str[count-1], address))
			return 1;
		else
			return 0;
}


struct sockaddr_in set_address(char *address) {
    struct sockaddr_in recipient;
    bzero (&recipient, sizeof(recipient));
    recipient.sin_family = AF_INET;

    if(!inet_pton(AF_INET, address, &recipient.sin_addr)){
        // error
    }
	return recipient;
}

int main(int argc, char *argv[]){
    if (argc < 2){
        printf("no argument passed!\n");
		return EXIT_FAILURE;
    }

	struct sockaddr_in addr = set_address(argv[1]);
	
    char *address = argv[1];
    // check if correct here

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockfd < 0) {
		fprintf(stderr, "socket error: %s\n", strerror(errno)); 
		return EXIT_FAILURE;
	}

	struct timespec time_start;

    for(int ttl = 1; ttl <= 30; ttl++){
        setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));
        
        send_packages(&time_start, sockfd, addr,  ttl);

        if(receive_packages(&time_start ,sockfd, address, ttl) == 1)
			break;
	}
    
    return EXIT_SUCCESS;
}