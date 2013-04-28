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
 static void generate_initial_seq_num(context_t *ctx);
 static void control_loop(mysocket_t sd, context_t *ctx);


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

    /* TODO: state can be either established or FIN_WAIT_1 */
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
    our_dprintf("generated init seq %u\n", ctx->initial_sequence_num);
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
        our_dprintf("waiting on control loop event\n");
        /* TODO: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

        /* check whether it was the network, app, or a close request */
        /* TODO: fill in below. check for conj of two states? */

        if (event & NETWORK_DATA) {
            our_dprintf("network data received \n");
            /* there was network data received */
            /* TODO: check for FIN or receive data*/
            handle_cstate_est_recv(sd, ctx);
        } 
        if (event & APP_DATA) {
            our_dprintf("app data received \n");
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
            handle_cstate_est_send(sd, ctx);
        } 
        if (event & APP_CLOSE_REQUESTED) {
            /* the application has requested that the conn be closed */
            our_dprintf("close received \n");
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
    our_dprintf("in cstate closed\n");
    /* TODO: if closed from listen state, will it spin forever? */

    if (is_active) {
        send_syn_ack_fin(sd, ctx, SEND_SYN, ctx->initial_sequence_num, 0);
        ctx->connection_state = CSTATE_SYN_SENT;
    } else {
        ctx->connection_state = CSTATE_LISTEN;
    }
    return ret;
}

int handle_cstate_listen(mysocket_t sd, context_t * ctx) {
    our_dprintf("in cstate listen\n");
    int ret = 0;
    unsigned int event;

    /* TODO: you will need to change some of these arguments!*/
    event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

    /* check whether it was the network, app, or a close request */

    if (event & NETWORK_DATA) {
        /* there was network data received */

        /* TODO: check endianness */
        /* TODO: do we need to check for data here? */
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
            ctx->initial_recd_seq_num = tcp_packet->th_seq; /*TODO: is +1 correct */
            our_dprintf("init recv seq : %u, amount recd %u\n" ,ctx->initial_recd_seq_num, recd);
            ctx->recd_last_byte_recd = ctx->initial_recd_seq_num;
            ctx->recd_next_byte_expected = ctx->recd_last_byte_recd + 1;
            our_dprintf("nbe = %u\n", ctx->recd_next_byte_expected);
            ctx->recd_adv_window = tcp_packet->th_win;
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

        /* TODO: if closed from listen state, will it spin forever? */
        ctx->connection_state = CSTATE_CLOSED;
    } 
    return ret;
}


int handle_cstate_syn_rcvd(mysocket_t sd, context_t * ctx) {

    int ret = 0;
    our_dprintf("in cstate syn rcvd\n");
    unsigned int event;

    /* TODO: you will need to change some of these arguments! how long to listen for */
    event = stcp_wait_for_event(sd, NETWORK_DATA | APP_CLOSE_REQUESTED | TIMEOUT, NULL);

    /* check whether it was the network, app, or a close request */
    if (event & NETWORK_DATA) {
        /* there was network data received */

        /* TODO: handle, check to see if theres an appropriate ack */
        /* TODO: check endianness */
        /* TODO: do we need to check for data here? */
        /* TODO: update ack num? */
        size_t recd;
        recd = stcp_network_recv(sd, ctx->recv_wind, MAX_WINDOW_SIZE);
        if (recd == 0) {
            our_dprintf("bad network recv\n");
            return -1;
        }

        struct tcphdr * tcp_packet  = (struct tcphdr *) ctx->recv_wind;

        if (tcp_packet->th_flags & TH_ACK){
            /* ack received */
            our_dprintf("got an ack : %u\n", tcp_packet->th_ack);
            if (tcp_packet->th_ack != ctx->sent_last_byte_sent + 1){
                our_dprintf("bad ack, expected %u, received %u. returning \n", ctx->sent_last_byte_sent+1, tcp_packet->th_ack);
                return -1;
            }
            ctx->sent_last_byte_acked = tcp_packet->th_ack;
            ctx->recd_adv_window = tcp_packet->th_win;
            ctx->connection_state = CSTATE_ESTABLISHED;
            our_dprintf("IN ESTABLISHED syn recv\n");
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
    our_dprintf("in cstate syn sent\n");
    unsigned int event;
    /* TODO: general check to make sure intial recd seq/ack line up */
    /* TODO: you will need to change some of these arguments! how long to listen for */
    our_dprintf("waiting for event \n");
    event = stcp_wait_for_event(sd, NETWORK_DATA | APP_CLOSE_REQUESTED | TIMEOUT, NULL);
    our_dprintf("got event: %x\n" , event);

    /* check whether it was the network, app, or a close request */
    if (event & NETWORK_DATA) {
        /* there was network data received */
        our_dprintf("got network data \n");
        /* TODO: check endianness */
        /* TODO: do we need to check for data here? */
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
            our_dprintf("got syn/ack. syn %u, ack %u, recd %u\n", tcp_packet->th_seq, tcp_packet->th_ack, recd_app);
            if (tcp_packet->th_ack != ctx->sent_last_byte_sent + 1){
                our_dprintf("bad ack, expected %u, received %u. returning \n", ctx->sent_last_byte_sent+1, tcp_packet->th_ack);
                return -1;
            }
            ctx->recd_adv_window = tcp_packet->th_win;
            ctx->initial_recd_seq_num = tcp_packet->th_seq;
            ctx->sent_last_byte_acked = tcp_packet->th_ack;
            ctx->recd_last_byte_recd = tcp_packet->th_seq ;
            ctx->recd_next_byte_expected = ctx->recd_last_byte_recd + 1;
            our_dprintf("next by exp = %u\n", ctx->recd_next_byte_expected);
            ctx->connection_state = CSTATE_ESTABLISHED;
            send_syn_ack_fin(sd, ctx, SEND_ACK, 0, 
                ctx->recd_next_byte_expected);// + 1);
            our_dprintf("IN ESTABLISHED syn sent\n");

        /* else if syn */
        } else if (tcp_packet->th_flags & TH_SYN){
            /* syn received */
            our_dprintf("got syn. syn %u, recd %u\n", tcp_packet->th_seq, tcp_packet->th_ack, recd);
            ctx->initial_recd_seq_num = tcp_packet->th_seq; /*TODO: is +1 correct */
            ctx->recd_last_byte_recd = tcp_packet->th_seq;
            ctx->recd_next_byte_expected = ctx->recd_last_byte_recd + 1;
            our_dprintf("ne by exp %u\n", ctx->recd_next_byte_expected);
            send_syn_ack_fin(sd, ctx, SEND_SYN | SEND_ACK, 
                ctx->initial_sequence_num, ctx->recd_next_byte_expected);
            ctx->recd_adv_window = tcp_packet->th_win;
            ctx->connection_state = CSTATE_SYN_RCVD;
        }

    } 
    if (event & APP_CLOSE_REQUESTED) {
        /* the application has requested that the conn be closed */
        our_dprintf("got close req\n"); 
        /* TODO: if closed from listen state, will it spin forever? */
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
    our_dprintf("in cstate fin wait 1\n");
    unsigned int event;

    /* TODO: you will need to change some of these arguments! how long to listen for */
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
            /* else if ack + fin */
            if (tcp_packet->th_ack != ctx->sent_last_byte_sent + 1){
                our_dprintf("bad ack, expected %u, received %u. returning \n", ctx->sent_last_byte_sent+1, tcp_packet->th_ack);
                return -1;
            }
            ctx->recd_last_byte_recd++;
            ctx->recd_last_byte_read++;
            ctx->recd_next_byte_expected++;
            send_syn_ack_fin(sd, ctx, SEND_ACK, 0, ctx->recd_next_byte_expected);
            ctx->connection_state = CSTATE_TIME_WAIT;
        } else if (tcp_packet->th_flags & TH_ACK){
            /* ack received */
            if (tcp_packet->th_ack != ctx->sent_last_byte_sent + 1){
                
                our_dprintf("bad ack, expected %u, received %u. returning \n", ctx->sent_last_byte_sent+1, tcp_packet->th_ack);
                our_dprintf("bad ack, expected %u, received %u. returning \n", ctx->sent_last_byte_sent+1, tcp_packet->th_ack);
                return -1;
            }
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
    our_dprintf("in cstate fin wait 2\n");
    unsigned int event;

    /* TODO: you will need to change some of these arguments! how long to listen for */
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

        if (tcp_packet->th_flags &  TH_FIN){
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
    our_dprintf("in cstate closing\n ");
    unsigned int event;

    /* TODO: you will need to change some of these arguments! how long to listen for */
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
            if (tcp_packet->th_ack != ctx->sent_last_byte_sent + 1){
                our_dprintf("bad ack, expected %u, received %u. returning \n", ctx->sent_last_byte_sent+1, tcp_packet->th_ack);
                return -1;
            }
            ctx->connection_state = CSTATE_TIME_WAIT;
        }

    } 

    return ret;    
}

int handle_cstate_time_wait(mysocket_t sd, context_t * ctx){
    int ret = 0;
    our_dprintf("in cstate time wait\n");


    ctx->connection_state = CSTATE_CLOSED;
    return ret;    
}

int handle_cstate_close_wait(mysocket_t sd, context_t * ctx){
    int ret = 0;
    our_dprintf("in cstate close wait\n");
    unsigned int event;

    /* TODO: set timeout appropriately, two seg lifetimes */
    event = stcp_wait_for_event(sd, APP_CLOSE_REQUESTED | TIMEOUT, NULL);

    /* check whether it was the network, app, or a close request */

    if (event & APP_CLOSE_REQUESTED) {
        /* there was network data received */

        /* TODO: send fin */
        send_syn_ack_fin(sd, ctx, SEND_FIN, 0, 0);
        ctx->connection_state = CSTATE_LAST_ACK;

    } 

    return ret;    
}

int handle_cstate_last_ack(mysocket_t sd, context_t * ctx){
    int ret = 0;

    unsigned int event;
    our_dprintf("in last ack\n");
    /* TODO: you will need to change some of these arguments! how long to listen for */
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
            if (tcp_packet->th_ack != ctx->sent_last_byte_sent + 1){
                our_dprintf("bad ack, expected %u, received %u. returning \n", ctx->sent_last_byte_sent+1, tcp_packet->th_ack);
                return -1;
            }
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

    /* TODO: add one byte for syn/fin? */


    /* TODO: check endianness */
    /* TODO: i think problem is here. make sure only syns/fins get a seq*/
    if (to_send_flags & SEND_SYN) {
        tcp_packet->th_seq = seq_num;
        tcp_packet->th_flags |= TH_SYN;
        ctx->sent_last_byte_written = seq_num;
        ctx->sent_last_byte_sent = seq_num;
    } else {
        tcp_packet->th_seq = ctx->sent_last_byte_sent + 1;
    }

    if (to_send_flags & SEND_ACK) {
        tcp_packet->th_ack = ack_num;
        tcp_packet->th_flags |= TH_ACK;
    } 

    if (to_send_flags & SEND_FIN) {
        tcp_packet->th_flags |= TH_FIN;
        ctx->sent_last_byte_sent++;
        ctx->sent_last_byte_written++;
        our_dprintf("sending fin , seq: %u\n",  ctx->sent_last_byte_sent);
    }

    tcp_packet->th_off = 5; /* no options, data begins 20 bytes into packet */

    /* set adv window size */
    tcp_packet->th_win = calc_adv_wind(ctx);
    ctx->sent_adv_window = tcp_packet->th_win;

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

    return ctx->recd_adv_window - (ctx->sent_last_byte_sent - ctx->sent_last_byte_acked);
}

int handle_cstate_est_recv(mysocket_t sd, context_t * ctx){
    our_dprintf("in cstate est recv\n "); 
    /* TODO: check incoming syn/ack/fin packets */
    size_t len =  sizeof(struct tcphdr) + ctx->sent_adv_window;
    uint8_t buff[len];
    uint32_t data_len, data_index;
    size_t delta, recv_len, recv_packet_len;
    recv_len = stcp_network_recv(sd, buff, len);
    our_dprintf("recvd %u bytes from network\n", recv_len);
    struct tcphdr * tcp_packet  = (struct tcphdr *) buff;
    size_t hdr_size = tcp_packet->th_off * 4;
    recv_packet_len = recv_len - 4 * tcp_packet->th_off;
    our_dprintf("header seq %u ack %u off %u flags %u win %u urp %u\n", tcp_packet->th_seq, tcp_packet->th_ack, tcp_packet->th_off, tcp_packet->th_flags, tcp_packet->th_win, tcp_packet->th_urp);

    /* check if any data was ack'd */
    if (tcp_packet->th_flags & TH_ACK) {
        if (tcp_packet->th_ack != ctx->sent_last_byte_sent + 1){
            our_dprintf("bad ack, expected %u, received %u. returning \n", ctx->sent_last_byte_sent+1, tcp_packet->th_ack);
            return -1;
        }
        ctx->sent_last_byte_acked = tcp_packet->th_ack;
        our_dprintf("got an ack in est recv: %u\n", tcp_packet->th_ack);
    }
    /* check to see if the seq number is appropriate */
    if (tcp_packet->th_seq != ctx->recd_next_byte_expected){
        our_dprintf("unexpected seq. rec seq : %u, expected : %u\n", tcp_packet->th_seq, ctx->recd_next_byte_expected);

        /* if part of the data is below the seq window */
        if ((tcp_packet->th_seq < ctx->recd_next_byte_expected) && 
            (tcp_packet->th_seq + recv_packet_len > ctx->recd_next_byte_expected)){
            our_dprintf("some data salvageable\n");
            /* some of the data should be salvaged */
            data_len = tcp_packet->th_seq + recv_packet_len - ctx->recd_next_byte_expected;
            data_index = recv_packet_len - data_len;
        } else if (0) {
            /* placeholder for if data overflows upper bound of sliding window */
            /* TODO: */


        } else {
            our_dprintf("bad packet\n");
            return 0;
        }
    } else {
        our_dprintf("seq number as expected \n");
        data_len = recv_packet_len;
        data_index = 0;
    }
    uint8_t * data = buff + hdr_size; /*TODO is this right?? */
    uint32_t wind_index = ((ctx->recd_last_byte_recd + 1) - ctx->initial_recd_seq_num) % MAX_WINDOW_SIZE;   
    our_dprintf("received data: %s\n", data);
    if (wind_index + data_len > MAX_WINDOW_SIZE){
        /* we're wrapping the buffer */
        delta = MAX_WINDOW_SIZE - wind_index;
        our_dprintf("wrapping recv buff \n");
        /*copy data to ctx->buffer and send it to app */ 
        memcpy(ctx->recv_wind + wind_index, data + data_index, delta); /* TODO: wind_index);// + 1 ?*/
        stcp_app_send( sd, ctx->recv_wind + wind_index, delta);

        memcpy(ctx->recv_wind, data + delta + data_index, data_len - delta);
        stcp_app_send( sd, ctx->recv_wind, data_len - delta);
        
    } else {
        /* we're not wrapping the buffer */
        our_dprintf("don't need to wrap, data len %d\n", data_len);
        /*copy data to ctx->buffer and send it to app */
        our_dprintf("data index %u\n", data_index); 
        memcpy(ctx->recv_wind + wind_index, data + data_index, data_len);
        stcp_app_send( sd, ctx->recv_wind + wind_index, data_len);
    }

    /* TODO: make sure these are set elsewhere as well. is this right? */
    ctx->recd_last_byte_recd += data_len;
    ctx->recd_next_byte_expected += data_len;
    ctx->recd_last_byte_read += data_len;
    /* TODO: is this too far delayed from receive? */

    if (data_len > 0 ) {
        our_dprintf("sending ack %u\n", ctx->recd_next_byte_expected);
        send_syn_ack_fin(sd, ctx, SEND_ACK, 0, ctx->recd_next_byte_expected);
    }

    if (tcp_packet->th_flags & TH_FIN) {
        our_dprintf("close req'd\n");
        stcp_fin_received(sd);
        if (data_len == 0){
            ctx->recd_last_byte_recd++;
            ctx->recd_next_byte_expected++;
            ctx->recd_last_byte_read++;
        }
        send_syn_ack_fin(sd, ctx, SEND_ACK, 0, ctx->recd_next_byte_expected);
        ctx->connection_state = CSTATE_CLOSE_WAIT;
        close_tcp_conn(sd, ctx);
        /* TODO: send another ack? */
    }
    our_dprintf("done, returning\n");
    return 0;
    
}




int handle_cstate_est_send(mysocket_t sd, context_t * ctx){
    our_dprintf("in cstate est send\n");
    size_t eff_wind = calc_eff_window(ctx);
    size_t max_to_send = MIN(eff_wind, STCP_MSS);
    if (max_to_send == 0) {
        our_dprintf("window too small to send, returning \n");
        return 0;
    }
    our_dprintf("max to send %u\n", max_to_send);
    /* receive data from app */
    size_t recd_app;
    uint8_t buff[max_to_send];
    recd_app = stcp_app_recv(sd, buff, max_to_send);

    our_dprintf("recd %u bytes from app: %s\n",recd_app, buff);
    /* construct header */
    uint32_t header_size = sizeof(struct tcphdr);
    uint8_t header_buf[header_size];
    memset(header_buf, 0, header_size);

    struct tcphdr * tcp_header = ( struct tcphdr *) header_buf;

    tcp_header->th_seq = ctx->sent_last_byte_sent + 1;
    tcp_header->th_flags |= TH_SYN;
    

    tcp_header->th_off = 5; /* no options, data begins 20 bytes into packet */

    /* set adv window size */
    tcp_header->th_win = calc_adv_wind(ctx);
    ctx->sent_adv_window = tcp_header->th_win;
    our_dprintf("sending adv wind %u\n", tcp_header->th_win);

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
        our_dprintf("send wind buff %s\n", ctx->send_wind + wind_index);
        stcp_network_send(sd, header_buf, header_size, (ctx->send_wind + wind_index), recd_app, NULL);
    }
    ctx->sent_last_byte_sent += recd_app;

    ctx->sent_last_byte_written += recd_app;
    our_dprintf("last sent %u, last written %u\n", ctx->sent_last_byte_sent, ctx->sent_last_byte_written);
    our_dprintf("done. sent %u bytes, returning \n", recd_app);
    return 0;

}
