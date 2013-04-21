
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


