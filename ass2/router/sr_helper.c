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

int sr_handle_arp_req (struct sr_instance * sr, struct sr_arpreq * arpreq, uint8_t * eth_source, int len,
      uint32_t sender_ip, uint32_t dest_ip, char * iface) {

      assert(arpreq);
      time_t now;
      time(&now);

      if (difftime(now, arpreq->sent) <= 1.0){
            fprintf(stderr, "arpreq less than 1 sec\n");
            return 0;
      }

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
      return 0;
}

struct sr_rt* find_best_rt(struct sr_rt* routing_table, uint32_t ip) {
      /* Find out which entry in the routing table has 
      the longest prefix match with the 
      destination IP address. */

      struct sr_rt* ip_rt_walker = routing_table;

      uint32_t dest, mask, maxlen = 0;
      struct sr_rt* best_rt = NULL;

      while (ip_rt_walker){
      	dest = ntohl(ip_rt_walker->dest.s_addr);
      	mask = ntohl(ip_rt_walker->mask.s_addr);
      	if ((dest & mask) == (ip & mask)) {
      		fprintf(stderr, "found matching destination in rt\n");
      		if (mask > maxlen){
      			maxlen = mask;
      			best_rt = ip_rt_walker;
      		}
      	}
      	ip_rt_walker = ip_rt_walker->next;
      }

      return best_rt;
}

int handle_ip_packet(struct sr_instance * sr, uint8_t * packet, unsigned int len ) {


      sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

      /* validate checksum. */
      uint16_t checksum;

      checksum = cksum(iphdr, sizeof(*iphdr));
      if (checksum != 0xffff) {
            fprintf(stderr, "incorrect checksum\n");
            return -1;
      } 

      uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));

      /* ICMP */
      if (ip_proto == ip_protocol_icmp) { 

            /* TODO: handle icmp */
            fprintf(stderr, "got ICMP packet\n");
            int minlength = sizeof(sr_icmp_hdr_t) + sizeof(sr_ethernet_hdr_t);
            if (len < minlength){
                  fprintf(stderr, "Failed to parse ICMP header, insufficient length\n");
                  return -1;
            }
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

            if (new_iphdr->ip_ttl <= 0) {
                /* check ttl, less than zero */
                  fprintf(stderr, "ttl was 0 after decrementing, returning\n");
                  return -1;
            }

            /* update checksum. */
            new_iphdr->ip_sum = 0;
            checksum = cksum(new_iphdr, sizeof(*new_iphdr));
            new_iphdr->ip_sum = checksum;
            checksum = cksum(new_iphdr, sizeof(*new_iphdr));
            if (checksum != 0xffff){
                  fprintf(stderr, "bad new check sum\n");
            }

            /* Find out which entry in the routing table has 
            the longest prefix match with the 
            destination IP address. */
            struct sr_rt* best_rt = find_best_rt(sr->routing_table,  ntohl(new_iphdr->ip_dst));         

            if (!best_rt) {
                  /* didn't find an interface, TODO: send an ICMP message type 3 
                  code 0, also if there are any errors above */
            }

            /* found an interface */
            fprintf(stderr, "we have an interface to send on: %s\n", best_rt->interface);

            struct sr_if * best_iface = sr_get_interface(sr, best_rt->interface);
            if (!best_iface){
                  fprintf(stderr, "bad iface lookup\n");
                  return -1;
            }
            struct sr_arpentry * forward_arp_entry = sr_arpcache_lookup(&(sr->cache), ntohl(best_rt->gw.s_addr));
            struct sr_ethernet_hdr * new_ether_hdr = (struct sr_ethernet_hdr * ) newpacket_for_ip; 

                  /* ethernet -- update the source address */
            memcpy(new_ether_hdr->ether_shost, best_iface->addr,  ETHER_ADDR_LEN);

            if (forward_arp_entry) {
                  /* we have a MAC address */
                  fprintf(stderr, "we have a MAC address: %s\n", forward_arp_entry->mac);

                  /* update packet */
                  /* ethernet -- set the dest address */
                  memcpy(new_ether_hdr->ether_dhost, forward_arp_entry->mac, ETHER_ADDR_LEN);

                        /* send packet using correct interface */
                  int res = 0; 

                  fprintf(stderr, "about to forward ip newpacket\n");
                  res = sr_send_packet(sr, newpacket_for_ip, len, best_rt->interface);

                  if (res != 0) {
                        fprintf(stderr, "bad sr_send_packet IP\n");
                        return -1;
                  }

                  free(forward_arp_entry);
                  return 0;
            } else {
                  /* we dont have a MAC address, add to arp queue */
                  fprintf(stderr, "no mac address =( queueing an arpreq\n");
                  struct sr_arpreq * arpreq;
                  arpreq = sr_arpcache_queuereq(&(sr->cache), best_rt->gw.s_addr, newpacket_for_ip, 
                        len, best_rt->interface );
                  if (!arpreq){
                        fprintf(stderr, "bad arpreq \n");
                        return -1;
                  }
                  uint32_t ip, dest;
                  fprintf(stderr, "interface ip = ");
                  print_addr_ip_int(ntohl(best_iface->ip));
                  ip = ntohl(best_iface->ip);

                  dest = ntohl(best_rt->dest.s_addr);
                  sr_handle_arp_req (sr, arpreq, best_iface->addr, ETHER_ADDR_LEN, ip, dest, best_rt->interface); 

                  return 0;
            } 
      }
      return 0;
}


struct sr_rt* validate_ip(struct sr_rt * routing_table, uint32_t ip) {

      /* check to see if the target IP belongs to one of our routers */
      struct sr_rt* rt_walker = routing_table;
      while(rt_walker){
            if (ntohl(rt_walker->dest.s_addr) ==  ntohl(ip)){
                  return rt_walker;
            }
            rt_walker = rt_walker->next;
      }     
      return NULL;
}


int send_arp_response(struct sr_instance * sr, struct sr_rt * assoc_iface_rt, uint8_t * packet, unsigned int len) {

      int res; 

      /* look up MAC address in interface list by interface name */
      struct sr_if* assoc_iface = sr_get_interface(sr, assoc_iface_rt->interface);
      if(!assoc_iface){
            fprintf(stderr, "couldnt find MAC:\n");
            return -1;
      }
      /* we have a MAC address */
      uint8_t newpacket[len];
      memcpy(newpacket, packet, len);
      struct sr_arp_hdr * new_arp_hdr = (sr_arp_hdr_t *)(newpacket + sizeof(sr_ethernet_hdr_t));
      struct sr_ethernet_hdr* ether_hdr = (struct sr_ethernet_hdr *) newpacket;

      /* send it back to whoever sent it (ethernet) */
      memcpy(ether_hdr->ether_dhost, ether_hdr->ether_shost, ETHER_ADDR_LEN);

      /* make sure the ethernet packet header is updated with the new mac */
      memcpy(ether_hdr->ether_shost, assoc_iface->addr, ETHER_ADDR_LEN);

      /* take the old sender address and make it the target */
      memcpy(new_arp_hdr->ar_tha, new_arp_hdr->ar_sha, ETHER_ADDR_LEN);

      /* load in the discovered MAC address as the sender address */
      memcpy(new_arp_hdr->ar_sha, assoc_iface->addr, ETHER_ADDR_LEN);

      uint32_t temp = new_arp_hdr->ar_tip;

      /* send it back to the IP we got it from */
      new_arp_hdr->ar_tip = new_arp_hdr->ar_sip;

      /* replace IP with what it was sent to */
      new_arp_hdr->ar_sip = temp;

      /* set arp op to reply */
      new_arp_hdr->ar_op = htons(arp_op_reply);

      fprintf(stderr, "about to send arp reply\n");
      print_hdrs(newpacket, len);
      res = sr_send_packet(sr, newpacket, len, assoc_iface_rt->interface);

      if (res != 0) {
            fprintf(stderr, "bad sr_send_packet ARP\n");
            return -1;
      }
      return 0;
}

int handle_arp_reply(struct sr_instance * sr, uint8_t * packet, unsigned int len){

      struct sr_arp_hdr *arp_hdr = (struct sr_arp_hdr *)(packet + sizeof(sr_ethernet_hdr_t));
      struct sr_arpentry *arpentry = sr_arpcache_lookup(&(sr->cache), arp_hdr->ar_sip);

      /* if entry isn't already in cache */
      if (arpentry) {
            fprintf(stderr, "entry already in cache\n");
            return 0;
      }

      struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

      /* if there were requests pending on this IP */
      if(!req){
            fprintf(stderr, "there were no req pending on this IP\n");
            return 0;
      }

      struct sr_packet * to_send = req->packets;
      struct sr_ethernet_hdr * ethr_to_send;
      int res;

      /* send all packets waiting on this IP */
      while (to_send){

            /* update the mac address of each ethernet frame */
            ethr_to_send = (struct sr_ethernet_hdr *) to_send->buf;
            memcpy(ethr_to_send->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);

            res = sr_send_packet(sr, to_send->buf, to_send->len, to_send->iface);

            if (res != 0){
                  fprintf(stderr, "bad packet send after arp reply\n");
                  continue;
            }
            to_send = to_send->next;
      }
      return 0;
}

int handle_arp_packet(struct sr_instance * sr, uint8_t * packet, unsigned int len ){

      int res;

      struct sr_arp_hdr *arp_hdr = (struct sr_arp_hdr *)(packet + sizeof(sr_ethernet_hdr_t));
      int arp_op = ntohs(arp_hdr->ar_op);

      print_hdrs(packet, len);

      /* check to see if the target IP belongs to one of our routers */
      struct sr_rt* assoc_iface_rt = validate_ip(sr->routing_table, arp_hdr->ar_sip); 

      /* if its not one of ours, ignore it */
      if (!assoc_iface_rt){
            fprintf(stderr, "doesn't belong to one of our interfaces, returning\n\n");
            return -1;
      }

      if (arp_op == arp_op_request){ 
            /* this is an incoming request */
            fprintf(stderr, "got arp req\n");

            res = send_arp_response(sr, assoc_iface_rt,  packet,  len);

            if (res != 0){
                  fprintf(stderr, "bad send_arp_response\n");
                  return -1;
            }


      } else if (arp_op == arp_op_reply) { 
            /* this is an incoming reply */
            fprintf(stderr, "got arp reply\n");
            print_hdrs(packet, len);

            res = handle_arp_reply(sr, packet, len);
            if (res != 0){
                  fprintf(stderr, "bad handle_arp_reply\n");
                  return -1;
            }
      } else { 
            /* bad arp_op type */
            fprintf(stderr, "unknown arp_op type\n");
            return -1;
      }
      return 0;
}
