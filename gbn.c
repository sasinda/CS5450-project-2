#include "gbn.h"

const int ACCPT_BUFLEN = DATALEN + HEADLEN; //1024+48

const struct timeval TV_VAL = {TIMEOUT, 0};
const struct timeval TV_ZERO = {0, 0};
const struct timeval TV_MIN_VAL = {0, 1000};//2nd value is micro seconds. So Min timeout is 1 millis

void make_syn_pack(gbnhdr *seg, int seq_num);

void make_synack_pack(gbnhdr *seg, int seq_num);

void make_data_pack(gbnhdr *seg, const void *buff, size_t len, uint8_t seq_num);

gbnhdr make_dataack_pack(gbnhdr *seg, uint8_t seq_num);

void make_fin_pack(gbnhdr *seg, int seq_num);

void make_finack_pack(gbnhdr *seg, int seq_num);

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
int move_window(struct window_elem *window, int win_len);

void settimers(struct window_elem *tot_window, int win_len);

void handle_timeout(int snum);

void init_window(struct window_elem pElem[2], int i);

int adjust_window_size(struct window_elem *window, int current_size);

struct window_elem *last_win_elem(struct window_elem *win, int win_size);

int min(int a, int b);

bool csum_correct(gbnhdr *ptr);

state_t sm;


int min(int a, int b){
    if(a<b) return a;
    else return b;
}

void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *) sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *) sa)->sin6_addr);
}


uint16_t checksum(uint8_t *buf, int nwords) {
    uint16_t sum;
    for (sum = 0; nwords > 0; nwords--) {
        sum += *buf++;
    }
    sum = (sum >> 8) + (sum & 0xff);
    sum += (sum >> 8);
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
        int confirmed_idx = 0;
        int nxt_idx = 0;
        void *nxt = buf;
        int curr_widx = 0;
        struct window_elem win[MAX_WINDOW_SIZE];
        init_window(win, MAX_WINDOW_SIZE);
        int win_size = 1;

        while (confirmed_idx < len) {
            curr_widx = 0;
            while (curr_widx < win_size) {
                struct window_elem *cwin = &win[curr_widx++];
                struct timeval now;
                gettimeofday(&now, NULL);
                if (cwin->buf == NULL) {
                    //new packet
                    if ((len - nxt_idx) >= DATALEN) {
                        cwin->buf_len = DATALEN;
                    } else {
                        cwin->buf_len = len - nxt_idx;
                    }
                    if (cwin->buf_len == 0) {
                        cwin->buf = NULL;
                        continue;
                    }
                    cwin->buf = nxt;
                    cwin->exp_on = TV_ZERO;
                    cwin->seq_num = sm.seq_num++;
                    nxt = nxt + cwin->buf_len;
                    nxt_idx += cwin->buf_len;
                    printf("gbn_send: new packet with seq: %d : payload %d bytes\n", cwin->seq_num, cwin->buf_len);
                } else if (cwin->data_acked || timercmp(&cwin->exp_on, &now, >)) {
                    //either an acked packet not removed from window( cant be)
                    // or packet is still not yet expired.
                    continue;
                } else {
                    //expired packet.
                    cwin->exp_on = TV_ZERO;
                    //reset expire on
                    printf("gbn_send: seq: %d had timed out. Resending\n", cwin->seq_num);
                }
                gbnhdr seg;
                make_data_pack(&seg, cwin->buf, cwin->buf_len, cwin->seq_num);
                maybe_sendto(sockfd, &seg, seg.length, 0, &sm.dest_sock_addr, sm.dest_sock_len);
                cwin->data_acked = false;
            }
            //Wait for data ack. Sets up the timers internally.
            wait_for_dataack(win, win_size);
            confirmed_idx += move_window(win, win_size);
            win_size = adjust_window_size(win, win_size);
            struct window_elem *lst = last_win_elem(win, win_size);
            if (lst != NULL && lst->buf != NULL) {
                nxt = lst->buf + lst->buf_len;
                nxt_idx = nxt - buf;
            }

        }
        sent = confirmed_idx;
        printf("sent %d bytes", sent);
    } else {
        printf("Cannot send. Connection state %d", sm.state);
    }
    return sent;
}

struct window_elem *last_win_elem(struct window_elem *win, int win_size) {
    for (int i = win_size - 1; i >= 0; i--) {
        if (win[i].buf != NULL) {
            return &win[i];
        }
    }
    return NULL;
}


int wait_for_dataack(struct window_elem *window, int win_size) {

    struct sockaddr_storage their_addr;
    socklen_t addr_len;
    gbnhdr dataack;

    //Setup the timers before waiting to recv.
    settimers(window, win_size);
    int num_bytes = recvfrom(sm.sockfd, &dataack, ACCPT_BUFLEN, 0,
                             (struct sockaddr *) &their_addr, &addr_len);

    if (num_bytes > 0 && dataack.type == DATAACK) {
        //TODO range check is wrong, when seq number wraps around.
        uint8_t w_start = (uint8_t) (window[0].seq_num);
        uint8_t w_end = (uint8_t) (window[win_size - 1].seq_num);
        bool in_range = true;
        const uint8_t da_seqnum = dataack.seqnum;
        if (w_start <= w_end) {
            in_range = (w_start < da_seqnum && da_seqnum <= w_end + 1);
        } else {
            in_range = ((0 <= da_seqnum && da_seqnum <= w_end + 1) || (w_start < da_seqnum <= 255));
        }
        if (in_range) {
            int j = 0;
            do {
                window[j].data_acked = true;
                sm.num_cont_success += 1;
                sm.num_cont_fail = 0;
                ++j;
            } while (window[j].seq_num != da_seqnum && j < win_size);
            printf("gbn_send: window [%d:%d], data ack %d\n", w_start, w_end, da_seqnum);
        } else if (window[0].seq_num == da_seqnum) {
            //none of the seg in current window was sent successfully.
        } else {
            printf("Got data ack (%d) out of range for the current window. %d to %d expected.\n", da_seqnum,
                   w_start, w_end);
            //If it was higher than the current acceptable, i.e a malfunctioning or malicious receiver.
        }
    } else if (num_bytes < 0 && errno == EINTR) {
        //We timed out.
        //just return to main loop in parent func. It'll resend unacked packets
    }
    return 0;
}


ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags) {
    //TODO discard out of order and wait.
    gbnhdr data_seg;
    struct sockaddr_storage their_addr;
    socklen_t addr_len;

    int data_len = -1;
    while (1) {
        int numbytes = recvfrom(sockfd, &data_seg, min(ACCPT_BUFLEN, len + HEADLEN), 0,
                                (struct sockaddr *) &their_addr, &addr_len);
        if (numbytes > 0 &&  csum_correct(&data_seg)) {
            gbnhdr data_ack;

            if (data_seg.type == DATA && data_seg.seqnum == sm.seq_num ) {
                if (data_seg.length == numbytes) {
                    sm.seq_num = data_seg.seqnum + 1;
                    make_dataack_pack(&data_ack, sm.seq_num);
                    //send dataack , copy data to buffer and break.
                    sendto(sockfd, &data_ack, data_ack.length, 0, &sm.dest_sock_addr, sm.dest_sock_len);
                    memcpy(buf, data_seg.data, min(data_seg.length, len + HEADLEN));
                    printf("gbn_recv: %d bytes. Sent data ack for seq: %d\n", numbytes, data_ack.seqnum);
                    data_len = data_seg.length - HEADLEN;
                    break;
                }
                //else :no break. we didnt get the full segment. Or it was corrupted.
                // Just send a data_ack, saying we still expect this. and keep waiting on receive
            } else if (numbytes > 0 && data_seg.type == FIN) {
                sm.state = FIN_RCVD;
                data_len = 0;
                break;
            }
            //else: ignore out of seq packet or something.
            //re request for same sm.seq_num. Because we got outof order, or corrupted etc.
            make_dataack_pack(&data_ack, sm.seq_num);
            sendto(sockfd, &data_ack, data_ack.length, 0, &sm.dest_sock_addr, sm.dest_sock_len);
        } else {
            printf("gbn_recv: Corrupt data! seq?: %d", data_seg.seqnum);
        }
    }
    return data_len;
}

int gbn_close(int sockfd) {

    if (sm.state == ESTABLISHED) {
        int finsent = 0;
        uint8_t fin_seq_num = sm.seq_num++;
        while (finsent < 6) {

            finsent++;
            gbnhdr fin;
            make_fin_pack(&fin, fin_seq_num);
            int sent = sendto(sockfd, &fin, fin.length, 0, &sm.dest_sock_addr, sm.dest_sock_len);
            if (sent) {
                sm.state = FIN_SENT;
                gbnhdr finack;
                static struct itimerval timout;
                static struct itimerval timout_zero;

                timout.it_value = TV_VAL;
                timout.it_interval = TV_ZERO;
                timout_zero.it_value = TV_ZERO;
                timout_zero.it_interval = TV_ZERO;

                setitimer(ITIMER_REAL, &timout, NULL);

                int num_bytes = recvfrom(sm.sockfd, &finack, ACCPT_BUFLEN, 0,
                                         NULL, NULL);

                setitimer(ITIMER_REAL, &timout_zero, &timout);

                if (num_bytes > 0) {
                    if (finack.type == FINACK) {
                        printf("\n Fin ack recieved. Closing Socket. Bye bye!\n");
                        // wait or not check
                        return close(sockfd);
                    }
                }
            }
        }
        printf("Maximum FIN s retried. Aborting connection without FINACK.\n");
    }
    if (sm.state == FIN_RCVD) {
        gbnhdr fin_ack;
        make_finack_pack(&fin_ack, sm.seq_num);
        int sent = sendto(sockfd, &fin_ack, fin_ack.length, 0, &sm.dest_sock_addr, sm.dest_sock_len);
        // wait for two timeouts and then close
        return close(sockfd);
        //
    }
    if (sm.state == RST_RCVD) {
        return close(sockfd);

    }

    return close(sockfd);
}


int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen) {
    //connection message
    // send syn

    gbnhdr seg;
    make_syn_pack(&seg, sm.seq_num++);
    int tries = 0;
    while (tries++ < 5) {
        int sent = maybe_sendto(sockfd, &seg, seg.length, 0, server, socklen);
        struct sockaddr_storage their_addr;
        socklen_t addr_len;
        int numbytes;
        addr_len = sizeof their_addr;
        if (sent) {//wait for syn ack
            printf("waiting for syn ack\n");
            gbnhdr seg_recv;

            //set timeout
            static struct itimerval timout;
            static struct itimerval timout_zero;
            static struct timeval val = {5, 1};

            timout.it_value = val;
            timout.it_interval = TV_ZERO;
            timout_zero.it_value = TV_ZERO;
            timout_zero.it_interval = TV_ZERO;

            setitimer(ITIMER_REAL, &timout, NULL);

            numbytes = recvfrom(sockfd, &seg_recv, ACCPT_BUFLEN, 0,
                                (struct sockaddr *) &their_addr, &addr_len);
            setitimer(ITIMER_REAL, &timout_zero, &timout);

            if (numbytes > 0 && csum_correct(&seg_recv)) {
                if (seg_recv.type == SYNACK && seg_recv.seqnum == sm.seq_num) {
                    printf("recvd  SYNACK. Sending synack for threeway handshake \n", seg_recv.type);
                    gbnhdr seg_sack;
                    make_synack_pack(&seg_sack, sm.seq_num++);
                    maybe_sendto(sockfd, &seg_sack, seg_sack.length, 0, server, socklen);
                    sm.state = ESTABLISHED;
                    sm.dest_sock_addr = *server;
                    sm.dest_sock_len = socklen;
                    break;
                } else if (seg_recv.type == RST && seg_recv.seqnum == sm.seq_num) {
                    sm.state = RST_RCVD;
                    sleep(1);
                    continue;
                } else {
                    printf("gbn_connect: Received an unexpected packet. expected SYNACK with seq no %d", sm.seq_num);
                    continue;
                }
            } else {
                printf("gbn_connect: No data or Corrupted data. Error %s!\n", strerror(errno));
            }
            //else if timeout, sm state is -1, returned;
        }
    }
    if(sm.state!=ESTABLISHED){
        printf("gbn_connect: Connection timedout!. Max retries exceeded. Error is %s!\n", strerror(errno));
    }
    return sm.state;
}

bool csum_correct(gbnhdr *seg) {
    int orig = seg->checksum;
    seg->checksum = 0;
    bool ans = orig == checksum(seg, seg->length);
    seg->checksum = orig;
    return ans;
}

int gbn_listen(int sockfd, int backlog) {
    struct sockaddr_storage their_addr;
    socklen_t addr_len;
    char s[INET6_ADDRSTRLEN];
    int numbytes;

    printf("waiting for syn\n");
    addr_len = sizeof their_addr;
    gbnhdr seg;

    while (sm.state!=SYN_RCVD){
        numbytes = recvfrom(sockfd, &seg, ACCPT_BUFLEN, 0,
                            (struct sockaddr *) &their_addr, &addr_len);

        if(numbytes>0 && csum_correct(&seg)){
            printf("listener: got packet from %s\n",
                   inet_ntop(their_addr.ss_family,
                             get_in_addr((struct sockaddr *) &their_addr),
                             s, sizeof s));
            printf("listener: packet is %d bytes long\n", numbytes);
            if (seg.type == SYN) {
                sm.dest_sock_addr = *(struct sockaddr *) &their_addr;
                sm.dest_sock_len = addr_len;
                sm.state = SYN_RCVD;
                sm.seq_num = seg.seqnum + 1;
                gbnhdr synack;
                make_synack_pack(&synack, sm.seq_num);
                maybe_sendto(sockfd, &synack, synack.length, 0, &sm.dest_sock_addr, sm.dest_sock_len);
            } else {
                printf("listener: expecting a SYN. Client sent %s instead\n", packet_type_string(seg.type));
                numbytes = -1;
            }
        }
    }
    return numbytes;
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen) {
    sm.my_sock_addr = *server;
    sm.my_sock_len = socklen;
    return bind(sockfd, server, socklen);
}

int gbn_socket(int domain, int type, int protocol) {

    int sockfd = socket(domain, type, protocol);
    struct sigaction sact = {
            .sa_handler = handle_timeout,
            .sa_flags = 0,
    };
    sigaction(SIGALRM, &sact, NULL);

    sm.state = UNKNOWN;
    sm.sockfd = sockfd;
    /*----- Randomizing the seed. This is used by the rand() function -----*/
    srand((unsigned) time(0));
    sm.seq_num = 0;//(uint8_t) rand();
    return sockfd;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen) {
    if (sm.state == SYN_RCVD) {
        struct sockaddr_storage their_addr;
        socklen_t addr_len;
        char s[INET6_ADDRSTRLEN];
        int numbytes;

        printf("waiting for synack, for the three way handshake\n");
        addr_len = sizeof their_addr;
        gbnhdr packet;
        while (1) {
            numbytes = recvfrom(sockfd, &packet, ACCPT_BUFLEN, MSG_PEEK,
                                     (struct sockaddr *) &their_addr, &addr_len);
            printf("receiver: packet is %d bytes long\n", numbytes);
            if (numbytes > 0 && csum_correct(&packet)) {
                if (packet.type == DATA) {
                    //i.e 3rd ack from sender lost. My ack(2) was sent so the client(sender) assumes
                    // connection is establised, and is sending data.
                    //Just exit accept.
                    sm.state = ESTABLISHED;
                    sm.seq_num += 1;
                    printf("gbn_accept:Data recevied instead of synack in 3way.\n");
                    printf("gbn_accept: connection established with %s\n",
                           inet_ntop(their_addr.ss_family,
                                     get_in_addr((struct sockaddr *) &their_addr),
                                     s, sizeof s));
                    break;
                }
                //consume peeked massege.
                numbytes = recvfrom(sockfd, &packet, ACCPT_BUFLEN, 0,
                                    (struct sockaddr *) &their_addr, &addr_len);
                if (packet.type == SYNACK) {
                    //happy scenario
                    if (sm.seq_num == packet.seqnum) {
                        sm.state = ESTABLISHED;
                        sm.seq_num += 1;
                        printf("gbn_accept: ideal scenario\n");
                        printf("receiver: connection established with %s\n",
                               inet_ntop(their_addr.ss_family,
                                         get_in_addr((struct sockaddr *) &their_addr),
                                         s, sizeof s));
                        break;
                    } else {
                        printf("gbn_accept: error: Client trying to connect is sending a synack with a wrong seq number\n");
                    }
                } else if (packet.type == SYN) {
                    //resend synack
                    printf("gbn_accept: received a syn again. Lost synack. repeating synack.\n");
                    gbnhdr synack;
                    make_synack_pack(&synack, sm.seq_num);
                    maybe_sendto(sockfd, &synack, synack.length, 0, &sm.dest_sock_addr, sm.dest_sock_len);
                    continue;
                }
            } else{
                printf("gbn_accept: corrupted packet. looping again");
            }
        }
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


void make_syn_pack(gbnhdr *seg, int seq_num) {
    gbnhdr segi = {SYN, seq_num, 0, HEADLEN};
    *seg = segi;
    seg->checksum = checksum(seg, 6);
}


void make_fin_pack(gbnhdr *seg, int seq_num) {
    gbnhdr segi = {FIN, seq_num, 0, HEADLEN};
    *seg = segi;
    seg->checksum = checksum(seg, 6);
}

void make_finack_pack(gbnhdr *seg, int seq_num) {
    gbnhdr segi = {FINACK, seq_num, 0, HEADLEN};
    *seg = segi;
    seg->checksum = checksum(seg, 6);
}

void make_synack_pack(gbnhdr *seg, int seq_num) {
    gbnhdr segi = {SYNACK, seq_num, 0, HEADLEN};
    *seg = segi;
    seg->checksum = checksum(seg, 6);
}

void make_data_pack(gbnhdr *seg, const void *buff, size_t len, uint8_t seq_num) {
    gbnhdr segi = {DATA, seq_num, 0, HEADLEN};
    *seg = segi;
    memcpy(seg->data, buff, len);
    seg->length += len;
    seg->checksum = checksum(seg, seg->length);
}

gbnhdr make_dataack_pack(gbnhdr *seg, uint8_t seq_num) {
    gbnhdr segi = {DATAACK, seq_num, 0, HEADLEN};
    *seg = segi;
    seg->checksum = checksum(seg, 6);
}

int move_window(struct window_elem *window, int win_len) {
    int acked_data_amt = 0;
    int i = 0;
    while (window[i].buf != NULL && window[i].data_acked == true && i < win_len) {
//        printf("gbn_send: kicked out of win frame. seq: %d\n", window[i].seq_num);
        acked_data_amt += window[i].buf_len;
        window[i++].buf = NULL;

    }
    int j;
    for (j = 0; j < i && i < win_len; j++) {
        window[j] = window[i];
        window[i].buf = NULL;
        ++i;
    }
    return acked_data_amt;
}

int adjust_window_size(struct window_elem *window, int current_size) {
    int size = current_size;
    if (sm.num_cont_success >= current_size) {
        size = min(2 * current_size, MAX_WINDOW_SIZE);
    }
    if (sm.num_cont_fail > 0) {
        size = 1;
        //delete the othervalues.
        for (int i = 1; i < current_size; i++) {
            window[i].buf = NULL;
            window[i].buf_len = -1;
        }
        sm.seq_num = window[0].seq_num + 1;
    }
    if (size > current_size) {
        printf("gbn_send: fast mode. Win Size %d \n", size);
    } else if (size < current_size) {
        printf("gbn_send: slow mode. Win Size %d \n", size);
    }
    return size;
}

void init_window(struct window_elem *win, int win_len) {
    for (int i = 0; i < win_len; i++) {
        win[i].buf = NULL;
        win[i].buf_len = -1;
        win[i].data_acked = false;
    }
}


void handle_timeout(int snum) {
    printf("SIGALRM signum: %d\n", snum);
    sm.num_cont_success = 0;
    sm.num_cont_fail += 1;
    //reset the num success without timeouts to zero.
    //Then just return back to original flow. pack will be recent in the loop, since we have the state in window stlructure.
}

void settimers(struct window_elem *tot_window, int win_len) {

    static struct itimerval timeout;
    struct timeval now;
    gettimeofday(&now, NULL);
    struct timeval nxt_tout = TV_VAL;
    for (int i = 0; i < win_len; i++) {
        struct window_elem *w = &tot_window[i];
        if (!w->data_acked) {
            struct timeval temp;
            timeradd(&now, &TV_VAL, &temp);
            if (w->exp_on.tv_sec == 0) {
                //not yet initialized
                w->exp_on = temp;
            } else if (timercmp(&w->exp_on, &now, >)) {
                timersub(&w->exp_on, &now, &nxt_tout);
            } else {
                // we missed a timeout while in the send window loop or maybe right now in here.
                // Set next timeout to min timeouot, causes sigalarm almost immediately.
                nxt_tout = TV_MIN_VAL;
                w->exp_on = now;
            }
        }
    }
    if (timercmp(&nxt_tout, &TV_MIN_VAL, <)) {
        nxt_tout = TV_MIN_VAL;
    }
    timeout.it_value = nxt_tout;
    timeout.it_interval = TV_ZERO;
    setitimer(ITIMER_REAL, &timeout, NULL);
}


char *packet_type_string(int type) {
    static char *names[7] = {"SYN", "SYNACK", "DATA", "DATAACK", "FIN", "FINACK", "RST"};
    return names[type];
}


