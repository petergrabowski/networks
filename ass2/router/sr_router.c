
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
#include <string.h>
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

       /*function handle_arpreq(req):
       if difftime(now, req->sent) > 1.0
           if req->times_sent >= 5:
               send icmp host unreachable to source addr of all pkts waiting
                 on this request
               arpreq_destroy(req)
           else:
               send arp request
               req->sent = now
               req->times_sent++ 


        The struct sr_instance that represents the router contains a 
        list with all of the router's interfaces. An interface struct 
        contains the MAC address of the router.

        short answer - yes for the first part. you wouldn't do 
        anything with an ARP request that's not for one of your 
        interfaces. it's not your responsibility to ARP request 
        another router and then respond to a request
               */

        struct sr_arpentry * arpentry;

        fprintf(stderr, "got a packet, ARP\n");
        minlength += sizeof(sr_arp_hdr_t);
        if (len < minlength){
          fprintf(stderr, "Failed to parse ARP header, insufficient length\n");
        }
        sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
        int arp_op = ntohs(arp_hdr->ar_op)
        fprintf(stderr, "arp_op = %x\n", arp_op); 

        struct sr_arpreq * req;
        arpentry = sr_arpcache_lookup(&(sr->cache), arp_hdr->ar_sip);
        int found = 0;
        char   interface[sr_IFACE_NAMELEN];
      /* check to see if the target IP belongs to one of our routers */
        struct sr_rt* rt_walker = sr->routing_table;
        fprintf(stderr, "arp_hdr->ar_sip = %d\n" ,ntohl( arp_hdr->ar_sip));
        while(rt_walker){
         fprintf(stderr, "walker dest = %s, int form = %lu\n", inet_ntoa(rt_walker->dest), (unsigned long)ntohl(rt_walker->dest.s_addr));
         if (ntohl(rt_walker->dest.s_addr) ==  ntohl(arp_hdr->ar_sip)){
          found = 1;
          memcpy(interface, rt_walker->interface, sr_IFACE_NAMELEN);
          break;
        }
        rt_walker = rt_walker->next;
      }

      /* if its not one of ours, ignore it */
      if (!found){
        fprintf(stderr, "doesn't belong to one of our interfaces, returning\n\n");
        return;
      }

      if (arp_op == arp_op_request){ /* this is an incoming request */
      fprintf(stderr, "got arp req\n");

        /* look up MAC address in interface list by interface name */
      found = 0;
      struct sr_if * if_walker = sr->if_list;
      unsigned char   mac_addr[ETHER_ADDR_LEN];
      fprintf(stderr, "interface %s\n", interface);

      while (if_walker){
        fprintf(stderr, "if_walker interface = %s\n", if_walker->name);
        if (strncmp(interface, if_walker->name, sr_IFACE_NAMELEN) == 0){
          memcpy(mac_addr, if_walker->addr, ETHER_ADDR_LEN);
          found = 1;
          break;
        }
        if_walker = if_walker->next;
      }

        /* send ARP response */
      if(found){
        fprintf(stderr, "found MAC:\n");
        DebugMAC(mac_addr);
      } else {
        fprintf(stderr, "couldnt find MAC:\n");
      }
      } else if (arp_op == arp_op_reply) { /* this is an incoming reply */
      fprintf(stderr, "got arp reply\n");
      } else { /* bad arp_op type */
      fprintf(stderr, "unknown arp_op type\n");
      return;
    }

      /* if entry isn't already in cache */
    if (!arpentry) {
      req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

        /* if there were requests pending on this IP */
      if(req){
          /* TODO: there were reqs waiting. send packets */
        ;

      }
      } else { /* entry isn't in cache, we need to send ARP req */

    }

    sr_arpcache_dump(&(sr->cache));
  } /* end ARP */
    else {
      fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
    }
  /* TODO: fill in code here */
    return;
} /* end sr_ForwardPacket */
