
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
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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
        char* interface/* lent */)
  {
  /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

  /*(printf("*** -> Received packet of length %d, packet = %d, interface = %s \n",len, *packet, interface);*/

  /* Sanity-check the packet 
     meets minimum length */ 
    if (len < 42 || len > 1500){
      fprintf(stderr, "packet was outside size reqs: len = %d\n", len);
      return;
    }
    
    fprintf(stderr, "got a packet, processing\n");

    /* print_hdrs(packet, len); */

  /* Ethernet */
    int minlength = sizeof(sr_ethernet_hdr_t);
    if (len < minlength) {
      fprintf(stderr, "Failed to parse ETHERNET header, insufficient length\n");
      return;
    }

    uint16_t ethtype = ethertype(packet);
    /* print_hdr_eth(buf); 
    fprintf(stderr, "ethtype = %d", ethtype); */
  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (len < minlength) {
      fprintf(stderr, "Failed to parse IP header, insufficient length\n");
      return;
    }

    fprintf(stderr, "done with ethernet, now doing IP\n");
    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* and has correct checksum. */
    uint16_t checksum;

    checksum = cksum(iphdr, sizeof(*iphdr));
    if (checksum != iphdr->ip_sum) {
      fprintf(stderr, "incorrect checksum\n");
      return;
    } else {
      fprintf(stderr, "correct checksum!\n");
    }

    uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
    if (ip_proto == ip_protocol_icmp) { /* ICMP */
    minlength += sizeof(sr_icmp_hdr_t);
    if (len < minlength)
      fprintf(stderr, "Failed to parse ICMP header, insufficient length\n");
    } /* end ICMP */
  } /* end IP */
  else if (ethtype == ethertype_arp) { /* ARP */
      struct sr_arpentry * arpentry;
      fprintf(stderr, "got a packet, ARP\n");
      minlength += sizeof(sr_arp_hdr_t);
      if (len < minlength)
        fprintf(stderr, "Failed to parse ARP header, insufficient length\n");
      sr_arpcache_dump(&(sr->cache));
  } /* end ARP */
  else {
      fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
  /* TODO: fill in code here */
  return;
} /* end sr_ForwardPacket */
