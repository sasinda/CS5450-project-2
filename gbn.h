#ifndef _gbn_h
#define _gbn_h

#include <arpa/inet.h>
#include <tgmath.h>
#include <sys/time.h>

#include<sys/types.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<signal.h>
#include<unistd.h>
#include<fcntl.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<time.h>
#include <stdbool.h>

/*----- Error variables -----*/
extern int h_errno;
extern int errno;

/*----- Protocol parameters -----*/
#define LOSS_PROB 1e-2    /* loss probability                            */
#define CORR_PROB 1e-3    /* corruption probability                      */
#define DATALEN   1024    /* length of the payload                       */
#define HEADLEN   6    /* length of the header in bytes                      */
#define N         1024    /* Max number of packets a single call to gbn_send can process */
#define TIMEOUT      2    /* timeout to resend packets (1 second)        */

#define MAX_WINDOW_SIZE 2


/*----- Packet types -----*/
#define SYN      0        /* Opens a connection                          */
#define SYNACK   1        /* Acknowledgement of the SYN packet           */
#define DATA     2        /* Data packets                                */
#define DATAACK  3        /* Acknowledgement of the DATA packet          */
#define FIN      4        /* Ends a connection                           */
#define FINACK   5        /* Acknowledgement of the FIN packet           */
#define RST      6        /* Reset packet used to reject new connections */


/*----- Go-Back-n packet format -----*/
typedef struct {
	uint8_t  type;            /* packet type (e.g. SYN, DATA, ACK, FIN)     */
	uint8_t  seqnum;          /* sequence number of the packet              */
    uint16_t checksum;        /* header and payload checksum                */
	uint16_t  length;		  /* length in bytes for the data/payload. */
    uint8_t data[DATALEN];    /* pointer to the payload                     */
} __attribute__((packed, aligned(1))) gbnhdr;

typedef struct state_t{
	uint8_t state;
	int sockfd;
	uint8_t seq_num;//contains the next seq num to send a packet with, or the next expected seq num
	int num_cont_success;
	int num_cont_fail;
    struct sockaddr my_sock_addr;
    socklen_t my_sock_len;
    struct sockaddr dest_sock_addr;
    socklen_t dest_sock_len;


} state_t;

typedef struct window_elem{
	void *buf;
	int  buf_len;
	uint8_t seq_num;
	struct timeval exp_on;
	bool data_acked;
};

enum {
	UNKNOWN=-1,
	CLOSED=0,
	SYN_SENT,
	SYN_RCVD,
	ESTABLISHED,
	FIN_SENT,
	FIN_RCVD,
	RST_RCVD
};

extern state_t sm;

void gbn_init();
int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen);
int gbn_listen(int sockfd, int backlog);
int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen);
int gbn_socket(int domain, int type, int protocol);
int gbn_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int gbn_close(int sockfd);
ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags);

ssize_t  maybe_sendto(int  s, const void *buf, size_t len, int flags, \
                      const struct sockaddr *to, socklen_t tolen);

uint16_t checksum(uint8_t *buf, int nwords);


void deserialize_gbnhdr(const uint8_t* buffer, const int* buf_len,  gbnhdr *segment);

char* packet_type_string(int type);

#endif
