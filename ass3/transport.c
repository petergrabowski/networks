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
    control_loop(sd, ctx);

    /* do any cleanup here */
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
    /* assign a random initial seq num from 0 - 2^32-1 */
    ctx->initial_sequence_num = rand() % (4294967296 -1);
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

        /* TODO: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

        /* check whether it was the network, app, or a close request */
        /* TODO: fill in below. check for conj of two states? */

        if (event & APP_DATA) {
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */

        } 
        if (event & NETWORK_DATA) {
            /* there was network data received */

            /* TODO: check for FIN or receive data*/
        } 
        if (event & APP_CLOSE_REQUESTED) {
            /* the application has requested that the conn be closed */

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
        ctx->connection_state != CSTATE_FIN_WAIT_1) {
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
            perror("bad open tcp conn state");
            assert(0);
            break;
        }
    }
    return 0;
}

int handle_cstate_closed(mysocket_t sd, context_t * ctx, bool_t is_active) {

    int ret = 0;

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

    int ret = 0;
    unsigned int event;

    /* TODO: you will need to change some of these arguments!*/
    event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

    /* check whether it was the network, app, or a close request */
    if (event & APP_DATA) {
        /* the application has requested that data be sent */

        send_syn_ack_fin(sd, ctx, SEND_SYN, ctx->initial_sequence_num, 0);
        ctx->connection_state = CSTATE_SYN_SENT;
    } 

    if (event & NETWORK_DATA) {
        /* there was network data received */

        /* TODO: check endianness */
        /* TODO: do we need to check for data here? */
        size_t recd;
        recd = stcp_network_recv(sd, ctx->recv_wind, MAX_WINDOW_SIZE);
        if (recd == 0) {
            perror("bad network recv");
            return -1;
        }

        struct tcphdr * tcp_packet  = (struct tcphdr *) ctx->recv_wind;

        if (tcp_packet->th_flags & TH_SYN){
            /* syn received */
            ctx->initial_recd_seq_num = tcphdr->th_seq + 1; /*TODO: is +1 correct */
            send_syn_ack_fin(sd, ctx, SEND_SYN | SEND_ACK, 
                ctx->initial_sequence_num, ctx->initial_recd_seq_num);

            ctx->connection_state = CSTATE_SYN_RCVD;
        }

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
            perror("bad network recv");
            return -1;
        }

        struct tcphdr * tcp_packet  = (struct tcphdr *) ctx->recv_wind;

        if (tcp_packet->th_flags & TH_ACK){
            /* ack received */

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

    /* TODO: you will need to change some of these arguments! how long to listen for */
    event = stcp_wait_for_event(sd, NETWORK_DATA | APP_CLOSE_REQUESTED | TIMEOUT, NULL);

    /* check whether it was the network, app, or a close request */
    if (event & NETWORK_DATA) {
        /* there was network data received */

        /* TODO: check endianness */
        /* TODO: do we need to check for data here? */
        size_t recd;
        recd = stcp_network_recv(sd, ctx->recv_wind, MAX_WINDOW_SIZE);
        if (recd == 0) {
            perror("bad network recv");
            return -1;
        }

        struct tcphdr * tcp_packet  = (struct tcphdr *) ctx->recv_wind;

        /* if syn + ack */
        if (tcp_packet->th_flags & (TH_SYN | TH_ACK)) {
            send_syn_ack_fin(sd, ctx, SEND_ACK, 0, 
                ctx->initial_recd_seq_num + 1);
            ctx->connection_state = CSTATE_ESTABLISHED;

        /* else if syn */
        } else if (tcp_packet->th_flags & TH_SYN){
            /* syn received */
            ctx->initial_recd_seq_num = tcphdr->th_seq + 1; /*TODO: is +1 correct */

            send_syn_ack_fin(sd, ctx, SEND_SYN | SEND_ACK, 
                ctx->initial_sequence_num, ctx->initial_recd_seq_num + 1);

            ctx->connection_state = CSTATE_SYN_RCVD;
        }

    } 

    if (event & APP_CLOSE_REQUESTED) {
        /* the application has requested that the conn be closed */

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
        }
    }
    ctx->done = TRUE;

    return 0;
}

int handle_cstate_fin_wait_1(mysocket_t sd, context_t * ctx){
    int ret = 0;

    unsigned int event;

    /* TODO: you will need to change some of these arguments! how long to listen for */
    event = stcp_wait_for_event(sd, NETWORK_DATA | TIMEOUT, NULL);

    /* check whether it was the network, app, or a close request */

    if (event & NETWORK_DATA) {
        /* there was network data received */

        /* if ack */
        ctx->connection_state = CSTATE_FIN_WAIT_2;

        /* else if ack + fin */
        send_syn_ack_fin(sd, ctx, SEND_ACK, 0, ctx->initial_recd_seq_num + 1);
        ctx->connection_state = CSTATE_TIME_WAIT;

        /* else if fin */
        send_syn_ack_fin(sd, ctx, SEND_ACK, 0, ctx->initial_recd_seq_num + 1);
        ctx->connection_state = CSTATE_CLOSING;

    } 

    return ret;    
}

int handle_cstate_fin_wait_2(mysocket_t sd, context_t * ctx){
    int ret = 0;

    unsigned int event;

    /* TODO: you will need to change some of these arguments! how long to listen for */
    event = stcp_wait_for_event(sd, NETWORK_DATA | TIMEOUT, NULL);

    /* check whether it was the network, app, or a close request */

    if (event & NETWORK_DATA) {
        /* there was network data received */

        /* if fin */
        /* TODO: send ack */
        send_syn_ack_fin(sd, ctx, SEND_ACK, 0, ctx->initial_recd_seq_num + 1);
        ctx->connection_state = CSTATE_TIME_WAIT;

    } 

    return ret;    
}

int handle_cstate_closing(mysocket_t sd, context_t * ctx){
    int ret = 0;

    unsigned int event;

    /* TODO: you will need to change some of these arguments! how long to listen for */
    event = stcp_wait_for_event(sd, NETWORK_DATA | TIMEOUT, NULL);

    /* check whether it was the network, app, or a close request */

    if (event & NETWORK_DATA) {
        /* there was network data received */

        /* if ack */
        ctx->connection_state = CSTATE_TIME_WAIT;

    } 

    return ret;    
}

int handle_cstate_time_wait(mysocket_t sd, context_t * ctx){
    int ret = 0;

    unsigned int event;

    /* TODO: set timeout appropriately, two seg lifetimes */
    event = stcp_wait_for_event(sd, TIMEOUT, NULL);

    /* check whether it was the network, app, or a close request */

    /* TODO: fill in below. check for conj of states? */
    if (event & TIMEOUT) {
        /* there was a timeout  */

        ctx->connection_state = CSTATE_CLOSED;

    } 
    return ret;    
}

int handle_cstate_close_wait(mysocket_t sd, context_t * ctx){
    int ret = 0;

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

    /* TODO: you will need to change some of these arguments! how long to listen for */
    event = stcp_wait_for_event(sd, NETWORK_DATA | TIMEOUT, NULL);

    /* check whether it was the network, app, or a close request */

    if (event & NETWORK_DATA) {
        /* there was network data received */

        /* if ack */
        ctx->connection_state = CSTATE_CLOSED;

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

    if (to_send_flags & SEND_SYN) {
        tcp_packet->th_seq = seq_num;
        tcp_packet->th_flags |= TH_SYN;
    }

    if (to_send_flags & SEND_ACK) {
        tcp_packet->th_ack = ack_num;
        tcp_packet->th_flags |= TH_ACK;
    }

    if (to_send_flags & SEND_FIN) {
        tcp_packet->th_flags |= TH_FIN;
    }

    tcp_packet->th_off = 5; /* no options, data begins 20 bytes into packet */

    /* TODO: set adv window size */

    /* send the newly constructed packet */ 
    ssize_t n;

    n = stcp_network_send(sd, buff , len, 0);
    if (n == -1){
        fprintf(stderr,"error: client bad send\n");
        perror("send");
        return -1;
    }



    return 0;
}
