
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
        char* interface/* lent */) {
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

    /* IP */
    if (ethtype == ethertype_ip) { 
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
        if (checksum != 0xffff) {
            fprintf(stderr, "incorrect checksum\n");
            return;
        } else {
            fprintf(stderr, "correct checksum!\n");
        }

        uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
        /* ICMP */
        if (ip_proto == ip_protocol_icmp) { 
            fprintf(stderr, "got ICMP packet\n");
            minlength += sizeof(sr_icmp_hdr_t);
            if (len < minlength)
                fprintf(stderr, "Failed to parse ICMP header, insufficient length\n");
            /* end ICMP */
        } else {
            /* not ICMP, reg IP packet */
            fprintf(stderr, "Got reg IP packet \n");
            uint8_t * newpacket_for_ip = (uint8_t *) malloc(len);
            memcpy(newpacket_for_ip, packet, len);
            sr_ip_hdr_t *new_iphdr = (sr_ip_hdr_t *)(newpacket_for_ip + sizeof(sr_ethernet_hdr_t));

            /* Decrement the TTL by 1, and recompute the packet 
            checksum over the modified header. */

            /* decrement ttl */
            new_iphdr->ip_ttl--;
            fprintf(stderr, "new ttl = %d\n", new_iphdr->ip_ttl);
            if (new_iphdr->ip_ttl <= 0) {
                /* check ttl, less than zero */
                fprintf(stderr, "ttl was 0 after decrementing, returning\n");
                return;
            }

            /* update checksum. TODO: do we need to zero 
            checksum first in ip hdr? */
            new_iphdr->ip_sum = 0;
            checksum = cksum(new_iphdr, sizeof(*new_iphdr));
            new_iphdr->ip_sum = checksum;
            checksum = cksum(new_iphdr, sizeof(*new_iphdr));
            if (checksum != 0xffff){
                fprintf(stderr, "bad new check sum\n");
            } else {
                fprintf(stderr, "good new check sum!\n");
            }
            /* Find out which entry in the routing table has 
            the longest prefix match with the 
            destination IP address. */

            struct sr_rt* ip_rt_walker = sr->routing_table;

            /* In order for an entry to match an IP, the 
            destination bit-wise ANDed with the mask must 
            equal the IP also bit-wise ANDed with the mask. 
            Among this subset, you choose the entry with 
            the longest mask. In the routing table provided,
            masks are 255.255.255.255, so matches must be 
            exact. Once you find a match, you send off the 
            packet to the gateway through the interface. */

            uint32_t dest, mask, ip, maxlen = 0;
            struct sr_rt* best_rt = NULL;

            /* TODO: do we need ntohl? */
            ip = ntohl(new_iphdr->ip_dst);

            while (ip_rt_walker){
                dest = ntohl(ip_rt_walker->dest.s_addr);
                mask = ntohl(ip_rt_walker->mask.s_addr);
		fprintf(stderr, "ip = %x, dest = %x, mask = %x\n", ip, dest, mask);
                if ((dest & mask) == (ip & mask)) {
                    fprintf(stderr, "found matching destination\n");
                    if (mask > maxlen){
                        maxlen = mask;
                        best_rt = ip_rt_walker;
                    }
                }
                ip_rt_walker = ip_rt_walker->next;
            }


            /* Check the ARP cache for the next-hop 
            MAC address corresponding to the next-hop 
            IP. If it's there, send it. Otherwise, 
            send an ARP request for the next-hop IP 
            (if one hasn't been sent within the last 
            second), and add the packet to the queue 
            of packets waiting on this ARP request. 
            Obviously, this is a very simplified 
            version of the forwarding process, and 
            the low-level details follow. For example, 
            if an error occurs in any of the above steps, 
            you will have to send an ICMP message back 
            to the sender notifying them of an error. 
            You may also get an ARP request or reply, 
            which has to interact with the ARP 
            cache correctly. 


            entry = arpcache_lookup(next_hop_ip)

            if entry:
                -- use next_hop_ip->mac mapping in 
                entry to send the packet
                -- free entry
            else:
                req = arpcache_queuereq(next_hop_ip, 
                                        packet, len)
                handle_arpreq(req)
            */

                if (best_rt) {
                    /* found an interface */
                    fprintf(stderr, "we have an interface to send on: %s\n", best_rt->interface);
                    struct sr_arpentry * forward_arp_entry;
                    
                    /* TODO: do we need ntohl() below? */
                    forward_arp_entry = sr_arpcache_lookup(&(sr->cache), best_rt->gw.s_addr);

                    if (forward_arp_entry) {
                        /* we have a MAC address */
                        fprintf(stderr, "we have a MAC address: %s\n", forward_arp_entry->mac);
                        struct sr_ethernet_hdr * new_ether_hdr = (struct sr_ethernet_hdr * ) newpacket_for_ip; 
                        struct sr_ethernet_hdr * old_ether_hdr = (struct sr_ethernet_hdr * ) packet; 

                        /* update packet */
                        /* ethernet -- update the source address */
                        memcpy(new_ether_hdr->ether_shost, old_ether_hdr->ether_dhost, ETHER_ADDR_LEN);

                        /* ethernet -- set the dest address */
                        memcpy(new_ether_hdr->ether_dhost, forward_arp_entry->mac, ETHER_ADDR_LEN);

                        /* send packet using correct interface */
                        int res = 0; 

                        fprintf(stderr, "about to forward ip newpacket\n");
                        res = sr_send_packet(sr, newpacket_for_ip, len, best_rt->interface);

                        if (res == 0) {
                            fprintf(stderr, "bad sr_send_packet IP\n");
                            return;
                        }

                    /* send it */
                    } else {
                        /* we dont have a MAC address, add to arp queue */
                        /* TODO: do we need ntohl() below? */

                        fprintf(stderr, "no mac address =( queueing an arpreq\n");
                        struct sr_arpreq * arpreq;
                        arpreq = sr_arpcache_queuereq(&(sr->cache), best_rt->gw.s_addr, newpacket_for_ip, 
                            len, best_rt->interface );
                        if (!arpreq){
                            fprintf(stderr, "bad arpreq \n");
                            return;
                        }

                      

                        /* TODO: write arpreq */
                        /* handle_arpreq(arpreq); */

                    }

                } else {
                /* didn't find an interface, TODO: send an ICMP message type 3 
                code 0, also if there are any errors above */
                }



            }
        /* end IP */
        } else if (ethtype == ethertype_arp) { 
        /* begin ARP */

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
        int arp_op = ntohs(arp_hdr->ar_op);
        fprintf(stderr, "arp_op = %x\n", arp_op); 

        struct sr_arpreq * req;

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
                fprintf(stderr,"iface name = %s\n", if_walker->name);
                fprintf(stderr,"found MAC addr '%s'\n", if_walker->addr);
                fprintf(stderr,"copied MAC addr %s\n", mac_addr);
                fprintf(stderr, "printing if entry\n");
                sr_print_if(if_walker);
                found = 1;
                break;
            }
            if_walker = if_walker->next;
        }

        /* TODO: send ARP response */
        if(found){
            fprintf(stderr, "found MAC:\n");
            DebugMAC(mac_addr);
            fprintf(stderr, "\n end debugmac \n");
            uint8_t newpacket[len];
            memcpy(newpacket, packet, len);
            sr_arp_hdr_t * new_arp_hdr = (sr_arp_hdr_t *)(newpacket + sizeof(sr_ethernet_hdr_t));
            struct sr_ethernet_hdr* ether_hdr = (struct sr_ethernet_hdr *) newpacket;

            /* send it back to whoever sent it (ethernet) */
            memcpy(ether_hdr->ether_dhost, ether_hdr->ether_shost, ETHER_ADDR_LEN);

            /* make sure the ethernet packet header is updated with the new mac */
            memcpy(ether_hdr->ether_shost, mac_addr, ETHER_ADDR_LEN);

            /* take the old sender address and make it the target */
            memcpy(new_arp_hdr->ar_tha, new_arp_hdr->ar_sha, ETHER_ADDR_LEN);

            /* load in the discovered MAC address as the sender address */
            memcpy(new_arp_hdr->ar_sha, mac_addr, ETHER_ADDR_LEN);

            uint32_t temp = new_arp_hdr->ar_tip;

            /* send it back to the IP we got it from */
            new_arp_hdr->ar_tip = new_arp_hdr->ar_sip;

            /* replace IP with what it was sent to */
            new_arp_hdr->ar_sip = temp;

            new_arp_hdr->ar_op = htons(arp_op_reply);

            int res = 0; 

            fprintf(stderr, "about to send newpacket\n");
            res = sr_send_packet(sr, newpacket, len, interface);
            
            if (res == 0) {
                fprintf(stderr, "bad sr_send_packet ARP\n");
                return;
            }
            fprintf(stderr, "sent newpacket\n");

            /* end found */
        } else {
            fprintf(stderr, "couldnt find MAC:\n");
        }

    } else if (arp_op == arp_op_reply) { 
        /* this is an incoming reply */
        fprintf(stderr, "got arp reply\n");

        arpentry = sr_arpcache_lookup(&(sr->cache), arp_hdr->ar_sip);
        
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
    } else { /* bad arp_op type */
        fprintf(stderr, "unknown arp_op type\n");
        return;
    }


    /* sr_arpcache_dump(&(sr->cache)); */

    /* end ARP */

} else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
}
    /* TODO: fill in code here */
return;

}
/* end sr_ForwardPacket */
