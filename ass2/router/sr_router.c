
/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_helper.h"


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

 void sr_init(struct sr_instance* sr)
 {
    /* REQUIRES */
  assert(sr);

    /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* TODO:  Add initialization code here! */

} /* -- sr_init -- */


  int sr_handle_arp_req (struct sr_instance * sr, struct sr_arpreq * arpreq, uint8_t * eth_source, int len,
    uint32_t sender_ip, uint32_t dest_ip, char * iface) {

    assert(arpreq);
    time_t now;
    time(&now);

    if (difftime(now, arpreq->sent) > 1.0){
        if (arpreq->times_sent >= 5){
            /* TODO: send icmp host unreachable to source addr of 
            all pkts waiting on this request */
         sr_arpreq_destroy(&(sr->cache), arpreq);
     } else {
        int minlength = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
        uint8_t arpbuf[minlength];
        memset(arpbuf, 0, minlength);
        struct sr_ethernet_hdr * eth_hdr = (struct sr_ethernet_hdr *) arpbuf;
        struct sr_arp_hdr * arp_hdr = (struct sr_arp_hdr *) (arpbuf + sizeof(sr_ethernet_hdr_t));

            /* TODO: is this correct */

            /* make sure its an ARP ethernet packet */
        eth_hdr->ether_type = ntohs(ethertype_arp);

            /* make the dest address FF:FF:FF:FF:FF:FF */
        int i;
        for (i = 0; i < ETHER_ADDR_LEN; i++){
            eth_hdr->ether_dhost[i] = 0xff;
        }

            /* set ethernet source address */
        memcpy(eth_hdr->ether_shost, eth_source, len);

            /* set arp hdr params */
        arp_hdr->ar_hrd = ntohs(1);
        arp_hdr->ar_pro = ntohs(2048);
        arp_hdr->ar_hln = 6;
        arp_hdr->ar_pln = 4;
        arp_hdr->ar_op = ntohs(arp_op_request);

            /* set arp hdr source mac address */ 
        memcpy(arp_hdr->ar_sha, eth_source, len);

            /* set arp hdr dest mac address to  FF:FF:FF:FF:FF:FF */ 
        memcpy(arp_hdr->ar_tha, eth_hdr->ether_dhost, ETHER_ADDR_LEN);

            /* set appropriate IPs */
        arp_hdr->ar_sip = ntohl(sender_ip);
        arp_hdr->ar_tip = ntohl(dest_ip);

            /* send packet using correct interface */
        int res = 0; 

        fprintf(stderr, "about to send arp req packet\n");
        print_hdr_eth(arpbuf);
        print_hdr_arp((uint8_t *) arp_hdr);
        res = sr_send_packet(sr, arpbuf, minlength, iface);

        if (res != 0) {
            fprintf(stderr, "bad sr_send_packet arp req\n");
            return -1;
        }

        arpreq->sent = now;
        arpreq->times_sent++;  
        return 0;
    }
}
return 0;
}


/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

 void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
    unsigned int len,
        char* interface/* lent */) {
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
    int res;
 
    fprintf(stderr, "\n\n*****   got a packet, processing\n");

    /* Ethernet */
    int minlength = sizeof(sr_ethernet_hdr_t);
    if (len < minlength) {
        fprintf(stderr, "Failed to parse ETHERNET header, insufficient length\n");
        return;
    }

    uint16_t ethtype = ethertype(packet);

    /* IP */
    if (ethtype == ethertype_ip) { 

        minlength += sizeof(sr_ip_hdr_t);
        if (len < minlength) {
            fprintf(stderr, "Failed to parse IP header, insufficient length\n");
            return;
        } 
        res = handle_ip_packet(sr, packet, len );

        if (res == -1){
            fprintf(stderr, "bad handle_ip_packet\n");
            return;
        }
        
        /* end IP */
    } else if (ethtype == ethertype_arp) { 
        /* begin ARP */

        fprintf(stderr, "got a packet, ARP\n");
        minlength += sizeof(sr_arp_hdr_t);

        if (len < minlength){
            fprintf(stderr, "Failed to parse ARP header, insufficient length\n");
        }
        res = handle_arp_packet(sr, packet, len );

        if (res == -1){
            fprintf(stderr, "bad handle_arp_packet\n");
            return;
        }
        /* end ARP */
    } else {
        fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
    }
    /* TODO: fill in code here */
    return;

}
/* end sr_ForwardPacket */


