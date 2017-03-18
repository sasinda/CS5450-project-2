#include "gbn.h"


const int ACCPT_BUFLEN = DATALEN + HEADLEN; //1024+48
char ACCEPT_BUFFER[ACCPT_BUFLEN];

void make_syn_pack(gbnhdr *seg);

void make_synack_pack(gbnhdr *seg);

void make_data_pack(gbnhdr *seg, const void *buff, size_t len);

gbnhdr make_dataack_pack(gbnhdr *seg, uint8_t seq_num);

/**
 * return the window index to iterate from.
 * @param win
 * @param win_size [out] curr win size
 * @param sidx [out] will be set to last data successfully sent without gaps
 * @return
 */
int wait_for_dataack(struct window_elem *win, int win_size);

/**
 * Moves the window and returns
 * @param window
 * @param win_len
 * @param sidx to return the last data successfully sent without gaps
 * @return sidx last data successfully sent without gaps
 */
int move_window(struct window_elem *window, int win_len, int sidx);

void settimers(struct window_elem *tot_window, int win_len);

void handle_timeout(int s);

void init_window(struct window_elem pElem[2], int i);

state_t sm;


void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *) sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *) sa)->sin6_addr);
}


uint16_t checksum(uint16_t *buf, int nwords) {
    uint32_t sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags) {
    /* Hint: Check the data length field 'len'.
     *       If it is > DATALEN, you will have to split the data
     *       up into multiple packets - you don't have to worry
     *       about getting more than N * DATALEN.
     */

    /**
     * Can send only if State is ESTABLISHED
     */
    int sent = -1;
    if (sm.state == ESTABLISHED) {
        sent = 0;
        int sidx = 0;
        void *nxt = buf;
        int curr_widx = 0;
        struct window_elem win[MAX_WINDOW_SIZE];
        init_window(win, MAX_WINDOW_SIZE);
        int win_size = 1;

        while (sidx < len) {
            curr_widx = 0;
            while (curr_widx < win_size) {
                struct window_elem *cwin = &win[curr_widx];
                if (cwin->buf == NULL) {
                    cwin->buf = nxt;
                    cwin->len = -1;
                } else if (cwin->data_acked || cwin->exp_on < (unsigned long) time(NULL)) {
                    continue;
                }

                gbnhdr seg;
                if ((len - sidx) > DATALEN) {
                    make_data_pack(&seg, cwin->buf, DATALEN);
                    sent += sendto(sockfd, &seg, seg.length, 0, &sm.dest_sock_addr, sm.dest_sock_len);
                } else {
                    make_data_pack(&seg, cwin->buf, len - sidx);
                    sent += sendto(sockfd, &seg, seg.length, 0, &sm.dest_sock_addr, sm.dest_sock_len);
                }
                if (cwin->len == -1) {
                    cwin->len = seg.length - HEADLEN;
                    nxt = buf + cwin->len;
                }
                cwin->data_acked = false;
                curr_widx += 1;
            }
            //Wait for data ack
            settimers(win, win_size);
            wait_for_dataack(&win, win_size);
            sidx = move_window(&win, win_size, sidx);
        }
    }
    printf("sent %d bytes", sent);
    return sent;
}


int wait_for_dataack(struct window_elem *window, int win_size) {
    struct sockaddr_storage their_addr;
    socklen_t addr_len;
    gbnhdr dataack;


    for (int i = 0; i < win_size; i++) {
        if (!window[i].data_acked) {
            int num_bytes = recvfrom(sm.sockfd, &dataack, ACCPT_BUFLEN - 1, 0,
                                     (struct sockaddr *) &their_addr, &addr_len);
            int j = -1;
            if (num_bytes > 0 && dataack.type == DATAACK) {
                while (window[++j].seq_num != dataack.seqnum && j < win_size) {
                }
                window[j].data_acked = true;
                sm.num_success += 1;
            } else if (num_bytes < 0 && errno == EINTR) {
                handle_timeout(errno);
                break;//return to main loop. It'll resend unacked packets
            }
        }
    }
    return 0;
}


ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags) {
    gbnhdr data_seg;
    struct sockaddr_storage their_addr;
    socklen_t addr_len;
    int numbytes = recvfrom(sockfd, &data_seg, ACCPT_BUFLEN - 1, 0,
                            (struct sockaddr *) &their_addr, &addr_len);
    if (numbytes > 0 && data_seg.type == DATA) {
        if (data_seg.length + HEADLEN == numbytes) {
            gbnhdr data_ack;
            //send dataack and the copy data to buffer.
            sendto(sockfd, &data_ack, data_ack.length, 0, &sm.dest_sock_addr, sm.dest_sock_len);
            memcpy(buf, data_seg.data, fmin(data_seg.length, len));
            printf("gbn_recv: %d bytes", numbytes);
        }
    }
    return numbytes;
}

int gbn_close(int sockfd) {
    return close(sockfd);
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen) {
    //connection message
    // send syn

    gbnhdr seg;
    make_syn_pack(&seg);
    int sent = sendto(sockfd, &seg, seg.length, 0, server, socklen);
    struct sockaddr_storage their_addr;
    socklen_t addr_len;
    int numbytes;
    addr_len = sizeof their_addr;
    if (sent) {//wait for syn ack
        printf("waiting for syn ack\n");
        gbnhdr seg_recv;

        //set timeout
        static struct itimerval timout;
        static struct timeval val = {2, 1};
        timout.it_value = val;
        timout.it_interval=val;
        setitimer(ITIMER_REAL, &timout, NULL);

        numbytes = recvfrom(sockfd, &seg_recv, ACCPT_BUFLEN - 1, 0,
                            (struct sockaddr *) &their_addr, &addr_len);
        if (numbytes > 0 && seg_recv.type == SYNACK) {
            printf("recvd  SYNACK. Sending synack for threeway handshake \n", seg_recv.type);
            gbnhdr seg_sack;
            make_synack_pack(&seg_sack);
            sendto(sockfd, &seg_sack, seg_sack.length, 0, server, socklen);
            sm.state = ESTABLISHED;
        } else {
            printf("gbn_connect: connection timed out!");
        }
        //else if timeout, sm state is -1, returned;
    }
    sm.dest_sock_addr = *server;
    sm.dest_sock_len = socklen;
    return sm.state;
}

int gbn_listen(int sockfd, int backlog) {
    struct sockaddr_storage their_addr;
    socklen_t addr_len;
    char s[INET6_ADDRSTRLEN];
    int numbytes;

    printf("waiting for syn\n");
    addr_len = sizeof their_addr;
    gbnhdr seg;
    if ((numbytes = recvfrom(sockfd, &seg, ACCPT_BUFLEN - 1, 0,
                             (struct sockaddr *) &their_addr, &addr_len)) == -1) {
        perror("recvfrom");
        exit(1);
    }

    printf("listener: got packet from %s\n",
           inet_ntop(their_addr.ss_family,
                     get_in_addr((struct sockaddr *) &their_addr),
                     s, sizeof s));
    printf("listener: packet is %d bytes long\n", numbytes);
    if (seg.type == SYN) {
        sm.dest_sock_addr = *(struct sockaddr *) &their_addr;
        sm.dest_sock_len = addr_len;
        sm.state = SYN_RCVD;
        gbnhdr synack;
        make_synack_pack(&synack);
        sendto(sockfd, &synack, synack.length, 0, &sm.dest_sock_addr, sm.dest_sock_len);
    }
    return numbytes;
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen) {
    sm.state = UNKNOWN;
    sm.sockfd = sockfd;
    sm.my_sock_addr = *server;
    sm.my_sock_len = socklen;
    return bind(sockfd, server, socklen);
}

int gbn_socket(int domain, int type, int protocol) {
    /*----- Randomizing the seed. This is used by the rand() function -----*/
    signal(SIGALRM, handle_timeout);
    srand((unsigned) time(0));
    return socket(domain, type, protocol);
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen) {
    struct sockaddr_storage their_addr;
    socklen_t addr_len;
    char s[INET6_ADDRSTRLEN];
    int numbytes;

    printf("waiting for synack, three way handshake\n");
    addr_len = sizeof their_addr;
    gbnhdr synack;
    if ((numbytes = recvfrom(sockfd, &synack, ACCPT_BUFLEN - 1, 0,
                             (struct sockaddr *) &their_addr, &addr_len)) == -1) {
        perror("error in accept");
        exit(1);
    }


    printf("receiver: packet is %d bytes long\n", numbytes);
    if (numbytes && synack.type == SYNACK) {
        sm.state = ESTABLISHED;
        printf("receiver: connection established with %s\n",
               inet_ntop(their_addr.ss_family,
                         get_in_addr((struct sockaddr *) &their_addr),
                         s, sizeof s));
    }
    return (sm.state == ESTABLISHED ? sockfd : -1);
}

ssize_t maybe_sendto(int s, const void *buf, size_t len, int flags, \
                     const struct sockaddr *to, socklen_t tolen) {

    char *buffer = malloc(len);
    memcpy(buffer, buf, len);


    /*----- Packet not lost -----*/
    if (rand() > LOSS_PROB * RAND_MAX) {
        /*----- Packet corrupted -----*/
        if (rand() < CORR_PROB * RAND_MAX) {

            /*----- Selecting a random byte inside the packet -----*/
            int index = (int) ((len - 1) * rand() / (RAND_MAX + 1.0));

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
        return (len);  /* Simulate a success */
}


/**
 * * @param segment The segment to send.
 * @param buffer copies the bytes of the packet to buffer
 * @param buf_len sets this to the length of the buffer filled.
 *
 */
void serialize_gbnhdr(gbnhdr *segment, uint8_t *buffer, int *buf_len) {
    memcpy(buffer, segment, segment->length);
    *buf_len = segment->length;
    return;
}


void make_syn_pack(gbnhdr *seg) {
    gbnhdr segi = {SYN, 0, 0, HEADLEN};
    *seg = segi;
    seg->checksum = checksum(&seg, 3);
}

void make_synack_pack(gbnhdr *seg) {
    gbnhdr segi = {SYNACK, 0, 0, HEADLEN};
    *seg = segi;
    seg->checksum = checksum(&seg, 3);
}

void make_data_pack(gbnhdr *seg, const void *buff, size_t len) {
    gbnhdr segi = {DATA, ++sm.seq_num, 0, HEADLEN};
    *seg = segi;
    memcpy(seg->data, buff, len);
    seg->length += len;
}

gbnhdr make_dataack_pack(gbnhdr *seg, uint8_t seq_num) {
    gbnhdr segi = {DATAACK, seq_num, 0, HEADLEN};
    *seg = segi;
}

int move_window(struct window_elem *window, int win_len, int sidx) {
    int i = 0;
    while (window[i].buf != NULL && window[i].data_acked == true && i < win_len) {
        sidx += window[i].len;
        window[i++].buf = NULL;
    }
    int j;
    for (j = 0; j < i && i < win_len; j++) {
        window[j] = window[i];
        window[i++].buf = NULL;
    }
    return sidx;
}

void init_window(struct window_elem *win, int win_len) {
    for (int i = 0; i < win_len; i++) {
        win[i].buf = NULL;
        win[i].len = -1;
        win[i].data_acked = false;
    }
}


void handle_timeout(int s) {
    printf("Data send timed out! %d", s);
    //do nothing. just retulrn back to original flow. pack will be recent in the loop, since we have the state in window stlructure.
}

void settimers(struct window_elem *tot_window, int win_len) {
    static const struct timeval TIMEOUT_T = {TIMEOUT, 0};
    static struct itimerval timout;
    timout.it_value = TIMEOUT_T;

    for (int i = 0; i < win_len; i++) {
        struct window_elem *w = &tot_window[i];
        if (!w->data_acked) {
            w->exp_on = (unsigned long) time(NULL) + TIMEOUT;
            w->timeout = timout;
        }
    }
    getitimer(ITIMER_REAL, &timout);

}



