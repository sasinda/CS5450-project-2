#include <arpa/inet.h>
#include "gbn.h"


const int ACCPT_BUFLEN=1025;
char ACCEPT_BUFFER[1025];

gbnhdr create_syn_pack();

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	
	/* TODO: Your code here. */

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

	return(-1);
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

	/* TODO: Your code here. */

	return(-1);
}

int gbn_close(int sockfd){

	/* TODO: Your code here. */

	return(-1);
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){
    //connection message
    create_syn_pack();
	gbnhdr seg;
	return sendto(sockfd, &seg, seg.length, 0, server, socklen);
}

int gbn_listen(int sockfd, int backlog){
    struct sockaddr_storage their_addr;
    socklen_t addr_len;
    char s[INET6_ADDRSTRLEN];
    int numbytes;

    printf("listener: waiting to recvfrom...\n");
    addr_len = sizeof their_addr;

    if ((numbytes = recvfrom(sockfd, ACCEPT_BUFFER, ACCPT_BUFLEN - 1 , 0,
                             (struct sockaddr *)&their_addr, &addr_len)) == -1) {
        perror("recvfrom");
        exit(1);
    }

    printf("listener: got packet from %s\n",
           inet_ntop(their_addr.ss_family,
                     get_in_addr((struct sockaddr *)&their_addr),
                     s, sizeof s));
    printf("listener: packet is %d bytes long\n", numbytes);
    ACCEPT_BUFFER[numbytes] = '\0';
    printf("listener: packet contains \"%s\"\n", ACCEPT_BUFFER);
    close(sockfd);
	return(-1);
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){
	return bind(sockfd, server, socklen);
}	

int gbn_socket(int domain, int type, int protocol){
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));
	return socket(domain, type, protocol);
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){

	/* TODO: Your code here. */

	return(-1);
}

ssize_t maybe_sendto(int  s, const void *buf, size_t len, int flags, \
                     const struct sockaddr *to, socklen_t tolen){

	char *buffer = malloc(len);
	memcpy(buffer, buf, len);
	
	
	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX){
		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB*RAND_MAX){
			
			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buffer[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buffer[index] = c;
		}

		/*----- Sending the packet -----*/
		int retval = sendto(s, buffer, len, flags, to, tolen);
		free(buffer);
		return retval;
	}
	/*----- Packet lost -----*/
	else
		return(len);  /* Simulate a success */
}



/**
 * * @param segment The segment to send.
 * @param buffer copies the bytes of the packet to buffer
 * @param buf_len sets this to the length of the buffer filled.
 *
 */
void serialize_gbnhdr(gbnhdr *segment, uint8_t *buffer, int* buf_len) {
    memcpy(buffer, segment, segment->length);
    *buf_len=segment->length;
    return;
}




gbnhdr create_syn_pack() {
	gbnhdr seg = {SYN, 0, 0, 6 };
	seg.checksum=checksum(&seg, 3);
	return seg;
}

gbnhdr create_data_pack(){

}