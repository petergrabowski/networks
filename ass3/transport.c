/*
 * transport.c 
 *
 * COS461: Assignment 3 (STCP)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include <time.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"

enum { 
        CSTATE_CLOSED,      /* connection is closed */
        CSTATE_LISTEN,      /* listening */
        CSTATE_SYN_RCVD,    /* syn has been received */
        CSTATE_SYN_SENT,    /* syn has been sent */
        CSTATE_ESTABLISHED, /* connection has been established, transmitting */
        CSTATE_FIN_WAIT_1,  /* first fin wait state */
        CSTATE_FIN_WAIT_2,  /* second fin wait state */
        CSTATE_CLOSING,     /* currently closing */
        CSTATE_TIME_WAIT,   /* waiting timeout */ 
        CSTATE_CLOSE_WAIT,  /* close wait state */
        CSTATE_LAST_ACK,    /* last ack */
 };    

 typedef struct
 {
    bool_t done;                      /* TRUE once connection is closed */
    
    int connection_state;             /* state of the connection (established, etc.) */
    
    tcp_seq initial_sequence_num;     /* local initial seq num */
    tcp_seq initial_recd_seq_num;     /* recd initial seq num */
    
    uint32_t sent_last_byte_acked;    /* the last byte that was ackd */
    uint32_t sent_last_byte_written;  /* the most recent written byte */
    uint32_t sent_last_byte_sent;     /* the last byte that was sent */
    
    uint32_t recd_last_byte_read;     /* the last byte that was read */
    uint32_t recd_last_byte_recd;     /* the last byte that was recd */
    uint32_t recd_next_byte_expected; /* the next byte that's expected */
    
    uint16_t sent_adv_window;         /* size of our adv window */
    uint16_t recd_adv_window;         /* size of the senders adv window */

    uint8_t * send_wind;
    uint8_t * recv_wind;

 } context_t;

 static void generate_initial_seq_num(context_t *ctx);
 static void control_loop(mysocket_t sd, context_t *ctx);

/* handle everything that happens before a connection is established */
int open_tcp_conn(mysocket_t sd, context_t * ctx, bool_t is_active);

/* handle a closed connection */
int handle_cstate_closed(mysocket_t sd, context_t * ctx, bool_t is_active);

/* listen for incoming network traffic */
int handle_cstate_listen(mysocket_t sd, context_t * ctx);

/* handle a connection after the syn has been rcvd */
int handle_cstate_syn_rcvd(mysocket_t sd, context_t * ctx);

/* handle a connection after a syn has been sent */
int handle_cstate_syn_sent(mysocket_t sd, context_t * ctx);

/* handle closing tcp conn */
int close_tcp_conn(mysocket_t sd, context_t * ctx);

/* handle state fin wait 1 */
int handle_cstate_fin_wait_1(mysocket_t sd, context_t * ctx);

/* handle state fin wait 2 */
int handle_cstate_fin_wait_2(mysocket_t sd, context_t * ctx);

/* handle the closing state */
int handle_cstate_closing(mysocket_t sd, context_t * ctx);

/* handle waiting for a timeout */
int handle_cstate_time_wait(mysocket_t sd, context_t * ctx);

/* handle close waiting */
int handle_cstate_close_wait(mysocket_t sd, context_t * ctx);

/* handle waiting for the last ack */
int handle_cstate_last_ack(mysocket_t sd, context_t * ctx);

int send_syn_ack_fin(mysocket_t sd, context_t * ctx, uint8_t to_send_flags, 
            tcp_seq seq_num, tcp_seq ack_num);

/* send data once a conn is established */
int handle_cstate_est_send(mysocket_t sd, context_t * ctx);

/* receive data once a conn is established */
int handle_cstate_est_recv(mysocket_t sd, context_t * ctx);

/* calc the size of the window to advertise */
uint16_t calc_adv_wind(context_t * ctx);

/* calc how much data is appropriate to send */
uint16_t calc_eff_window(context_t * ctx);

/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
 void transport_init(mysocket_t sd, bool_t is_active)
 {
    context_t *ctx;
    int res;
    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);
    ctx->connection_state = CSTATE_CLOSED;
    
    ctx->send_wind = (uint8_t *) malloc(MAX_WINDOW_SIZE);
    memset(ctx->send_wind, 0, MAX_WINDOW_SIZE);

    ctx->recv_wind = (uint8_t *) malloc(MAX_WINDOW_SIZE);
    memset(ctx->recv_wind, 0, MAX_WINDOW_SIZE);
    res = open_tcp_conn(sd, ctx, is_active);

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */

    stcp_unblock_application(sd);


    if (ctx->connection_state == CSTATE_ESTABLISHED){
        control_loop(sd, ctx);
    } else if (ctx->connection_state == CSTATE_FIN_WAIT_1){
        close_tcp_conn(sd, ctx);
    } else if (ctx->connection_state == CSTATE_CLOSED) {
        ;
    }else {
        our_dprintf("bad state in transport init");
        assert(0);
    }

    /* do any cleanup here */
    free(ctx->send_wind);
    free(ctx->recv_wind);
    free(ctx);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* assign a random initial seq num from 0 - 255 */
    srand(time(NULL) + (unsigned long int) ctx );
    ctx->initial_sequence_num = random() % 255;
#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
 static void control_loop(mysocket_t sd, context_t *ctx)
 {
    assert(ctx);
    assert(!ctx->done);
    while (!ctx->done)
    {
        unsigned int event;
        
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

        /* check whether it was the network, app, or a close request */
        
        if (event & NETWORK_DATA) {
            /* there was network data received */
            //our_dprintf("got network data\n");
            handle_cstate_est_recv(sd, ctx);
        } 
        if (event & APP_DATA) {
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
            handle_cstate_est_send(sd, ctx);
        } 
        if (event & APP_CLOSE_REQUESTED) {
            /* the application has requested that the conn be closed */
            //our_dprintf("close received \n");
            send_syn_ack_fin(sd, ctx, SEND_FIN, 0, 0);
            ctx->connection_state = CSTATE_FIN_WAIT_1;

            close_tcp_conn(sd, ctx);
        } 

    }
}


/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
 void our_dprintf(const char *format,...)
 {
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}

int open_tcp_conn(mysocket_t sd, context_t * ctx, bool_t is_active) {

    /* make sure the state is closed before we try to open it */
    assert(ctx->connection_state == CSTATE_CLOSED);
    while (ctx->connection_state != CSTATE_ESTABLISHED && 
        ctx->connection_state != CSTATE_FIN_WAIT_1 ) {
        switch(ctx->connection_state) {
            case CSTATE_CLOSED:
                /* connection is closed */
                handle_cstate_closed(sd, ctx, is_active);
                break;
            case CSTATE_LISTEN:
                /* listening */
                handle_cstate_listen(sd, ctx);
                break;
            case CSTATE_SYN_RCVD:
                /* syn has been received */
                handle_cstate_syn_rcvd(sd, ctx);
                break;
            case CSTATE_SYN_SENT:
                /* syn has been sent */
                handle_cstate_syn_sent(sd, ctx);
                break;
            default:
                /* shouldn't happen */
                our_dprintf("bad open tcp conn state\n");
                assert(0);
                break;
        }
    }
    return 0;
}

int handle_cstate_closed(mysocket_t sd, context_t * ctx, bool_t is_active) {

    int ret = 0;
    our_dprintf("in CSTATE_CLOSED\n");
    if (is_active) {
        send_syn_ack_fin(sd, ctx, SEND_SYN, ctx->initial_sequence_num, 0);
        ctx->connection_state = CSTATE_SYN_SENT;
    } else {
        ctx->connection_state = CSTATE_LISTEN;
    }
    return ret;
}

int handle_cstate_listen(mysocket_t sd, context_t * ctx) {
    int ret = 0;
    unsigned int event;

    our_dprintf("in CSTATE_LISTEN\n");
    
    event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

    /* check whether it was the network, app, or a close request */

    if (event & NETWORK_DATA) {
        /* there was network data received */

        size_t recd;
        recd = stcp_network_recv(sd, ctx->recv_wind, MAX_WINDOW_SIZE);
        if (recd == 0) {
            our_dprintf("bad network recv\n");
            return -1;
        }
        struct tcphdr * tcp_packet  = (struct tcphdr *) ctx->recv_wind;
        //size_t recd_app = recd - 4 * tcp_packet->th_off;
        if (tcp_packet->th_flags & TH_SYN){
            /* syn received */
            ctx->initial_recd_seq_num = ntohl(tcp_packet->th_seq); 
            ctx->recd_last_byte_recd = ctx->initial_recd_seq_num;
            ctx->recd_next_byte_expected = ctx->recd_last_byte_recd + 1;
            ctx->recd_adv_window = ntohs(tcp_packet->th_win);
            send_syn_ack_fin(sd, ctx, SEND_SYN | SEND_ACK, 
                ctx->initial_sequence_num, ctx->recd_next_byte_expected);
            ctx->connection_state = CSTATE_SYN_RCVD;
        }
    } 
    if (event & APP_DATA) {
        /* the application has requested that data be sent */
        send_syn_ack_fin(sd, ctx, SEND_SYN, ctx->initial_sequence_num, 0);
        ctx->connection_state = CSTATE_SYN_SENT;
    } 

    if (event & APP_CLOSE_REQUESTED) {
        /* the application has requested that the conn be closed */
        ctx->connection_state = CSTATE_CLOSED;
    } 
    return ret;
}


int handle_cstate_syn_rcvd(mysocket_t sd, context_t * ctx) {

    int ret = 0;
    unsigned int event;

    our_dprintf("in CSTATE_SYN_RCVD\n");
    event = stcp_wait_for_event(sd, NETWORK_DATA | APP_CLOSE_REQUESTED | TIMEOUT, NULL);

    /* check whether it was the network, app, or a close request */
    if (event & NETWORK_DATA) {
        /* there was network data received */

        size_t recd;
        recd = stcp_network_recv(sd, ctx->recv_wind, MAX_WINDOW_SIZE);
        if (recd == 0) {
            our_dprintf("bad network recv\n");
            return -1;
        }

        struct tcphdr * tcp_packet  = (struct tcphdr *) ctx->recv_wind;

        if (tcp_packet->th_flags & TH_ACK){
            /* ack received */
            if (ntohl(tcp_packet->th_ack) < ctx->sent_last_byte_acked || ntohl(tcp_packet->th_ack) > ctx->sent_last_byte_written+1){
                our_dprintf("bad ack, expected %u, received %u. returning \n", ctx->sent_last_byte_sent+1, tcp_packet->th_ack);
                return -1;
            }
            ctx->sent_last_byte_acked = ntohl(tcp_packet->th_ack);
            ctx->recd_adv_window = ntohs(tcp_packet->th_win);
            //our_dprintf("*** got ack %u, got adv window %u\n", ctx->sent_last_byte_acked, ctx->recd_adv_window);
            ctx->connection_state = CSTATE_ESTABLISHED;
        }
    } 

    if (event & APP_CLOSE_REQUESTED) {
        /* the application has requested that the conn be closed */

        ctx->connection_state = CSTATE_FIN_WAIT_1;
        close_tcp_conn(sd, ctx);
    } 
    return ret;
}

int handle_cstate_syn_sent(mysocket_t sd, context_t * ctx) {

    int ret = 0;
    unsigned int event;
    
    
    our_dprintf("in CSTATE_SYN_SENT\n");
    event = stcp_wait_for_event(sd, NETWORK_DATA | APP_CLOSE_REQUESTED | TIMEOUT, NULL);

    /* check whether it was the network, app, or a close request */
    if (event & NETWORK_DATA) {
        /* there was network data received */

        size_t recd, recd_app;
        recd = stcp_network_recv(sd, ctx->recv_wind, MAX_WINDOW_SIZE);
        if (recd == 0) {
            our_dprintf("bad network recv\n");
            return -1;
        }

        struct tcphdr * tcp_packet  = (struct tcphdr *) ctx->recv_wind;
        recd_app = recd - 4 * tcp_packet->th_off;
        /* if syn + ack */
        if (tcp_packet->th_flags & (TH_SYN | TH_ACK)) {
            if (ntohl(tcp_packet->th_ack) < ctx->sent_last_byte_acked || ntohl(tcp_packet->th_ack) > ctx->sent_last_byte_written+1){
                our_dprintf("bad ack, expected %u, received %u. returning \n", ctx->sent_last_byte_sent+1, tcp_packet->th_ack);
                return -1;
            }
            ctx->recd_adv_window = ntohs(tcp_packet->th_win);
            ctx->initial_recd_seq_num = ntohl(tcp_packet->th_seq);
            ctx->sent_last_byte_acked = ntohl(tcp_packet->th_ack);
            ctx->recd_last_byte_recd = ntohl(tcp_packet->th_seq);
            //our_dprintf("*** got ack %u, got adv win 3 = %u\n",ctx->sent_last_byte_acked ,ctx->recd_adv_window);
            ctx->recd_next_byte_expected = ctx->recd_last_byte_recd + 1;
            ctx->connection_state = CSTATE_ESTABLISHED;
            send_syn_ack_fin(sd, ctx, SEND_ACK, 0, 
                ctx->recd_next_byte_expected);

        /* else if syn */
        } else if (tcp_packet->th_flags & TH_SYN){
            /* syn received */
            ctx->initial_recd_seq_num = ntohl(tcp_packet->th_seq);
            ctx->recd_last_byte_recd = ntohl(tcp_packet->th_seq);
            ctx->recd_next_byte_expected = ctx->recd_last_byte_recd + 1;
            send_syn_ack_fin(sd, ctx, SEND_SYN | SEND_ACK, 
                ctx->initial_sequence_num, ctx->recd_next_byte_expected);
            ctx->recd_adv_window = ntohs(tcp_packet->th_win);

            if(tcp_packet->th_flags & TH_ACK){
                ctx->sent_last_byte_acked = ntohl(tcp_packet->th_ack);
            }
            ctx->connection_state = CSTATE_SYN_RCVD;
        }

    } 
    if (event & APP_CLOSE_REQUESTED) {
        /* the application has requested that the conn be closed */
        ctx->connection_state = CSTATE_CLOSED;
    } 
    return ret;
}


int close_tcp_conn(mysocket_t sd, context_t * ctx) {

    while(ctx->connection_state != CSTATE_CLOSED) {
        switch (ctx->connection_state) {

            case CSTATE_FIN_WAIT_1:
                /* first fin wait state */
                handle_cstate_fin_wait_1(sd, ctx);
                break;
            case CSTATE_FIN_WAIT_2:
                /* second fin wait state */
                handle_cstate_fin_wait_2(sd, ctx);
                break;
            case CSTATE_CLOSING:
                /* currently closing */
                handle_cstate_closing(sd, ctx);
                break;
            case CSTATE_TIME_WAIT:
                /* waiting timeout */ 
                handle_cstate_time_wait(sd, ctx);
                break;
            case CSTATE_CLOSE_WAIT:
                /* close wait state */
                handle_cstate_close_wait(sd, ctx);
                break;
            case CSTATE_LAST_ACK:
                /* last ack */
                handle_cstate_last_ack(sd, ctx);
                break;
            default:
                /* shouldn't happen */
                our_dprintf("bad close ctcp state\n");
                assert(0);
        }
    }
    ctx->done = TRUE;
    our_dprintf("ALL DONE\n");
    return 0;
}

int handle_cstate_fin_wait_1(mysocket_t sd, context_t * ctx){
    int ret = 0;
    unsigned int event;

    our_dprintf("in CSTATE_FIN_WAIT_1\n");
    event = stcp_wait_for_event(sd, NETWORK_DATA | TIMEOUT, NULL);

    /* check whether it was the network, app, or a close request */

    uint8_t buff[MAX_WINDOW_SIZE + sizeof(struct tcphdr)];
    if (event & NETWORK_DATA) {
        /* there was network data received */

        size_t recd;
        recd = stcp_network_recv(sd, buff, MAX_WINDOW_SIZE);
        if (recd == 0) {
            our_dprintf("bad network recv\n");
            return -1;
        }

        struct tcphdr * tcp_packet  = (struct tcphdr *) buff;

        if (tcp_packet->th_flags & (TH_ACK | TH_FIN)) {
            /* if ack + fin */
            if (ntohl(tcp_packet->th_ack) < ctx->sent_last_byte_acked || ntohl(tcp_packet->th_ack) > ctx->sent_last_byte_written+1){
                our_dprintf("bad ack, expected %u, received %u. returning \n", ctx->sent_last_byte_sent+1, tcp_packet->th_ack);
                return -1;
            }
            ctx->sent_last_byte_acked = ntohl(tcp_packet->th_ack);
            ctx->recd_last_byte_recd++;
            ctx->recd_last_byte_read++;
            ctx->recd_next_byte_expected++;
            send_syn_ack_fin(sd, ctx, SEND_ACK, 0, ctx->recd_next_byte_expected);
            ctx->connection_state = CSTATE_TIME_WAIT;
        } else if (tcp_packet->th_flags & TH_ACK){
            /* ack received */
            if (ntohl(tcp_packet->th_ack) < ctx->sent_last_byte_acked || ntohl(tcp_packet->th_ack) > ctx->sent_last_byte_written+1){
                
                our_dprintf("bad ack, expected %u, received %u. returning \n", ctx->sent_last_byte_sent+1, tcp_packet->th_ack);
                return -1;
            }
            ctx->sent_last_byte_acked = ntohl(tcp_packet->th_ack);
            //our_dprintf("*** got an ack %u\n", ctx->sent_last_byte_acked);
            ctx->connection_state = CSTATE_FIN_WAIT_2;

        } else if (tcp_packet->th_flags &  TH_FIN){
        /* else if fin */
            ctx->recd_last_byte_recd++;
            ctx->recd_last_byte_read++;
            ctx->recd_next_byte_expected++;
            send_syn_ack_fin(sd, ctx, SEND_ACK, 0, ctx->recd_next_byte_expected);
            ctx->connection_state = CSTATE_CLOSING;
        }

    } 

    return ret;    
}

int handle_cstate_fin_wait_2(mysocket_t sd, context_t * ctx){
    int ret = 0;
    unsigned int event;

    our_dprintf("in CSTATE_FIN_WAIT_2\n");
    event = stcp_wait_for_event(sd, NETWORK_DATA | TIMEOUT, NULL);

    /* check whether it was the network, app, or a close request */


    uint8_t buff[MAX_WINDOW_SIZE + sizeof(struct tcphdr)];
    if (event & NETWORK_DATA) {
        /* there was network data received */

        size_t recd;
        recd = stcp_network_recv(sd, buff, MAX_WINDOW_SIZE);
        if (recd == 0) {
            our_dprintf("bad network recv\n");
            return -1;
        }

        struct tcphdr * tcp_packet = (struct tcphdr *) buff;

        if (tcp_packet->th_flags & TH_FIN){
            /*  if fin */
            ctx->recd_last_byte_recd++;
            ctx->recd_last_byte_read++;
            ctx->recd_next_byte_expected++;
            send_syn_ack_fin(sd, ctx, SEND_ACK, 0, ctx->recd_next_byte_expected);
            ctx->connection_state = CSTATE_TIME_WAIT;
        }

    } 
    return ret;    
}

int handle_cstate_closing(mysocket_t sd, context_t * ctx){
    int ret = 0;
    unsigned int event;

    our_dprintf("in CSTATE_CLOSING\n");
    event = stcp_wait_for_event(sd, NETWORK_DATA | TIMEOUT, NULL);

    /* check whether it was the network, app, or a close request */
    uint8_t buff[MAX_WINDOW_SIZE + sizeof(struct tcphdr)];
    if (event & NETWORK_DATA) {
        /* there was network data received */

        size_t recd;
        recd = stcp_network_recv(sd, buff, MAX_WINDOW_SIZE);
        if (recd == 0) {
            our_dprintf("bad network recv\n");
            return -1;
        }

        struct tcphdr * tcp_packet  = (struct tcphdr *) buff;

        if (tcp_packet->th_flags & TH_ACK){
            /*  if ack */
            if (ntohl(tcp_packet->th_ack) < ctx->sent_last_byte_acked || ntohl(tcp_packet->th_ack) > ctx->sent_last_byte_written+1){
                our_dprintf("bad ack, expected %u, received %u. returning \n", ctx->sent_last_byte_sent+1, tcp_packet->th_ack);
                return -1;
            }
            //our_dprintf("*** got an ack %u\n", ctx->sent_last_byte_acked);
            ctx->sent_last_byte_acked = ntohl(tcp_packet->th_ack);
            ctx->connection_state = CSTATE_TIME_WAIT;
        }

    } 

    return ret;    
}

int handle_cstate_time_wait(mysocket_t sd, context_t * ctx){
    int ret = 0;


    ctx->connection_state = CSTATE_CLOSED;
    return ret;    
}

int handle_cstate_close_wait(mysocket_t sd, context_t * ctx){
    int ret = 0;
    unsigned int event;

    our_dprintf("in CSTATE_CLOSE_WAIT\n");
    struct timespec wait_time;
    time_t curtime;

    curtime = time(0);
    //our_dprintf("curtime = %u\n", curtime);
    wait_time.tv_sec = curtime + 240; /* wait atleast 2 lifetimes */
    wait_time.tv_nsec = 0; 
    event = stcp_wait_for_event(sd, APP_CLOSE_REQUESTED | TIMEOUT, &wait_time);

    /* check whether it was the network, app, or a close request */

    if (event & APP_CLOSE_REQUESTED) {
        /* there was network data received */

        send_syn_ack_fin(sd, ctx, SEND_FIN, 0, 0);
        ctx->connection_state = CSTATE_LAST_ACK;

    } 

    return ret;    
}

int handle_cstate_last_ack(mysocket_t sd, context_t * ctx){
    int ret = 0;

    unsigned int event;
    our_dprintf("in CSTATE_LAST_ACK\n");
    event = stcp_wait_for_event(sd, NETWORK_DATA | TIMEOUT, NULL);

    /* check whether it was the network, app, or a close request */

    uint8_t buff[MAX_WINDOW_SIZE + sizeof(struct tcphdr)];
    if (event & NETWORK_DATA) {
        /* there was network data received */

        size_t recd;
        recd = stcp_network_recv(sd, buff, MAX_WINDOW_SIZE);
        if (recd == 0) {
            our_dprintf("bad network recv\n");
            return -1;
        }

        struct tcphdr * tcp_packet  = (struct tcphdr *) buff;

        if (tcp_packet->th_flags & TH_ACK){
            /*  if ack */
            if (ntohl(tcp_packet->th_ack) < ctx->sent_last_byte_acked || ntohl(tcp_packet->th_ack) > ctx->sent_last_byte_written+1){
                our_dprintf("bad ack, expected %u, received %u. returning \n", ctx->sent_last_byte_sent+1, tcp_packet->th_ack);
                return -1;
            }
            //our_dprintf("*** got an ack %u\n", ctx->sent_last_byte_acked);
            ctx->sent_last_byte_acked = ntohl(tcp_packet->th_ack);
            ctx->connection_state = CSTATE_CLOSED;

        }

    } 
    return ret;    
}

int send_syn_ack_fin(mysocket_t sd, context_t * ctx, uint8_t to_send_flags, 
    tcp_seq seq_num, tcp_seq ack_num) {

    size_t len =  sizeof(struct tcphdr);
    uint8_t buff[len];

    struct tcphdr * tcp_packet  = (struct tcphdr *) buff;

    /* th_sport, th_dport, th_sum are set by network layer */
    /* th_urg is ignored by stcp*/

    if (to_send_flags & SEND_SYN) {
        tcp_packet->th_seq = htonl(seq_num);
        tcp_packet->th_flags |= TH_SYN;
        ctx->sent_last_byte_written = seq_num;
        ctx->sent_last_byte_sent = seq_num;
    } else {
        tcp_packet->th_seq = htonl(ctx->sent_last_byte_sent + 1);
    }

    if (to_send_flags & SEND_ACK) {
        tcp_packet->th_ack = htonl(ack_num);
        tcp_packet->th_flags |= TH_ACK;
        //our_dprintf("sending ack %u\n", ack_num);
    } 

    if (to_send_flags & SEND_FIN) {
        tcp_packet->th_flags |= TH_FIN;
        ctx->sent_last_byte_sent++;
        ctx->sent_last_byte_written++;
    }

    tcp_packet->th_off = 5; /* no options, data begins 20 bytes into packet */

    /* set adv window size */
    tcp_packet->th_win = htons(calc_adv_wind(ctx));
    ctx->sent_adv_window = calc_adv_wind(ctx);
    /* send the newly constructed packet */ 
    ssize_t n = stcp_network_send(sd, buff , len, 0);
    if (n == -1){
        fprintf(stderr,"error: client bad send\n");
        return -1;
    }

    return 0;
}

uint16_t calc_adv_wind(context_t * ctx) {
    return MAX_WINDOW_SIZE - ((ctx->recd_next_byte_expected - 1) - ctx->recd_last_byte_read);
}

uint16_t calc_eff_window(context_t * ctx) {
    //our_dprintf("EFF WINDOW :rec adv wind %u, last sent %u, last acked %u\n", ctx->recd_adv_window, ctx->sent_last_byte_sent, ctx->sent_last_byte_acked);
    return ctx->recd_adv_window - (ctx->sent_last_byte_sent - ctx->sent_last_byte_acked);
}

int handle_cstate_est_recv(mysocket_t sd, context_t * ctx){

    our_dprintf("* IN EST REC\n");
    size_t len =  sizeof(struct tcphdr) + STCP_MSS;
    uint8_t buff[len];
    uint32_t data_len, data_index;
    size_t delta, recv_len, recv_packet_len;
    recv_len = stcp_network_recv(sd, buff, len);
    struct tcphdr * tcp_packet  = (struct tcphdr *) buff;
    size_t hdr_size = tcp_packet->th_off * 4;
    recv_packet_len = recv_len - 4 * tcp_packet->th_off;

    /* check if any data was ack'd */
    if (tcp_packet->th_flags & TH_ACK) {
        if (ntohl(tcp_packet->th_ack) < ctx->sent_last_byte_acked || ntohl(tcp_packet->th_ack) > ctx->sent_last_byte_written+1){
            our_dprintf("bad ack, expected %u, received %u. returning \n", ctx->sent_last_byte_sent+1, tcp_packet->th_ack);
            return -1;
        }
        ctx->sent_last_byte_acked = ntohl(tcp_packet->th_ack);
        //our_dprintf("****got an ack: %u\n", tcp_packet->th_ack);
    }
    /* check to see if the seq number is appropriate */
    if (ntohl(tcp_packet->th_seq) != ctx->recd_next_byte_expected){
        //our_dprintf("unexpected seq. rec seq : %u, expected : %u\n", tcp_packet->th_seq, ctx->recd_next_byte_expected);

        /* if part of the data is below the seq window */
        if ((ntohl(tcp_packet->th_seq) < ctx->recd_next_byte_expected) && 
            (ntohl(tcp_packet->th_seq) + recv_packet_len > ctx->recd_next_byte_expected)){
            //our_dprintf("some data salvageable\n");
            /* some of the data should be salvaged */
            data_len = ntohl(tcp_packet->th_seq) + recv_packet_len - ctx->recd_next_byte_expected;
            data_index = recv_packet_len - data_len;
        } else if (0) {
            /* placeholder for if data overflows upper bound of sliding window */

        } else {
            //our_dprintf("bad packet\n");
            return 0;
        }
    } else {
        data_len = recv_packet_len;
        data_index = 0;
    }
    uint8_t * data = buff + hdr_size; 
    uint32_t wind_index = ((ctx->recd_last_byte_recd + 1) - ctx->initial_recd_seq_num) % MAX_WINDOW_SIZE;  
    //our_dprintf("window index %u, data len %u\n", wind_index, data_len); 
    //our_dprintf("received data: %s\n", data);
    if (wind_index + data_len > MAX_WINDOW_SIZE){
        /* we're wrapping the buffer */
        delta = MAX_WINDOW_SIZE - wind_index;
        //our_dprintf("wrapping recv buff \n");
        /*copy data to ctx->buffer and send it to app */ 
        memcpy(ctx->recv_wind + wind_index, data + data_index, delta); 
        stcp_app_send( sd, ctx->recv_wind + wind_index, delta);

        memcpy(ctx->recv_wind, data + delta + data_index, data_len - delta);
        stcp_app_send( sd, ctx->recv_wind, data_len - delta);
        
    } else {
        /* we're not wrapping the buffer */
        //our_dprintf("don't need to wrap, data len %d\n", data_len);
        /*copy data to ctx->buffer and send it to app */
        memcpy(ctx->recv_wind + wind_index, data + data_index, data_len);
        stcp_app_send( sd, ctx->recv_wind + wind_index, data_len);
    }

    ctx->recd_last_byte_recd += data_len;
    ctx->recd_next_byte_expected += data_len;
    ctx->recd_last_byte_read += data_len;

    if (data_len > 0 ) {
        //our_dprintf("acking %u bytes\n", data_len);
        send_syn_ack_fin(sd, ctx, SEND_ACK, 0, ctx->recd_next_byte_expected);
    } else {
        //our_dprintf("** flags %u\n", tcp_packet->th_flags);
    }
    

    if (tcp_packet->th_flags & TH_FIN) {
        stcp_fin_received(sd);
        if (data_len == 0){
            ctx->recd_last_byte_recd++;
            ctx->recd_next_byte_expected++;
            ctx->recd_last_byte_read++;
        }
        send_syn_ack_fin(sd, ctx, SEND_ACK, 0, ctx->recd_next_byte_expected);
        ctx->connection_state = CSTATE_CLOSE_WAIT;
        close_tcp_conn(sd, ctx);
    }
    return 0;
}




int handle_cstate_est_send(mysocket_t sd, context_t * ctx){
    //our_dprintf("*IN EST SEND\n");
    size_t eff_wind = calc_eff_window(ctx);
    size_t max_to_send = MIN(eff_wind, STCP_MSS);
    if (max_to_send == 0) {
        //our_dprintf("window too small to send min(%u, %u) \n", eff_wind, STCP_MSS);
        return 0;
    }
    //our_dprintf("max to send %u\n", max_to_send);
    /* receive data from app */
    size_t recd_app;
    uint8_t buff[max_to_send];
    recd_app = stcp_app_recv(sd, buff, max_to_send);

    /* construct header */
    uint32_t header_size = sizeof(struct tcphdr);
    uint8_t header_buf[header_size];
    memset(header_buf, 0, header_size);

    struct tcphdr * tcp_header = ( struct tcphdr *) header_buf;

    tcp_header->th_seq = htonl(ctx->sent_last_byte_sent + 1);
    tcp_header->th_flags |= TH_SYN;
    

    tcp_header->th_off = 5; /* no options, data begins 20 bytes into packet */

    /* set adv window size */
    tcp_header->th_win = htons(calc_adv_wind(ctx));
    ctx->sent_adv_window = calc_adv_wind(ctx);
    /* copy the data into the tcp buffer */

    uint32_t wind_index = ((ctx->sent_last_byte_written + 1) 
                - ctx->initial_sequence_num) % MAX_WINDOW_SIZE;
    our_dprintf("window index %u\n", wind_index);
    /* we're wrapping the buffer */
    if (wind_index + recd_app > MAX_WINDOW_SIZE) {
        size_t delta = MAX_WINDOW_SIZE - wind_index;
        our_dprintf("wrapping the buffer\n");
        /* fill the end of the buffer */
        memcpy(ctx->send_wind + wind_index, buff, delta);
        /* restart at the beginning of the buffer */
        memcpy(ctx->send_wind, buff+delta, recd_app - delta);

        stcp_network_send(sd, header_buf, header_size, ctx->send_wind + wind_index, delta, 
            ctx->send_wind, recd_app - delta, NULL);
    } else {
        /* don't need to wrap the buffer */
        our_dprintf("not wrapping the buffer\n");
        memcpy(ctx->send_wind + wind_index, buff, recd_app);
        stcp_network_send(sd, header_buf, header_size, (ctx->send_wind + wind_index), recd_app, NULL);
    }
    ctx->sent_last_byte_sent += recd_app;

    ctx->sent_last_byte_written += recd_app;
    return 0;

}
