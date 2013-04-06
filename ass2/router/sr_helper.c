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

int sr_handle_arp_req (struct sr_instance * sr, struct sr_arpreq * arpreq) {

      assert(arpreq);
      time_t now;
      time(&now);
      int res;
      if (difftime(now, arpreq->sent) <= 1.0){

            return 0;
      }

      if (arpreq->times_sent >= 5){
      /* send icmp host unreachable to source addr of 
      all pkts waiting on this request type 3 code 1*/
            struct sr_packet *packet_walker = arpreq->packets;
            while (packet_walker){
                  res = send_icmp_message(sr, packet_walker->buf, 3,  1);
                  if (res == -1){

                        return -1;
                  }
            }
            sr_arpreq_destroy(&(sr->cache), arpreq);
      }
      int minlength = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
      uint8_t arpbuf[minlength];
      memset(arpbuf, 0, minlength);
      struct sr_ethernet_hdr * eth_hdr = (struct sr_ethernet_hdr *) arpbuf;
      struct sr_arp_hdr * arp_hdr = (struct sr_arp_hdr *) (arpbuf + sizeof(sr_ethernet_hdr_t));

      /* make sure its an ARP ethernet packet */
      eth_hdr->ether_type = ntohs(ethertype_arp);

      /* make the dest address FF:FF:FF:FF:FF:FF */
      int i;
      for (i = 0; i < ETHER_ADDR_LEN; i++){
            eth_hdr->ether_dhost[i] = 0xff;
      }

      struct sr_rt* best_rt = find_best_rt(sr->routing_table, ntohl( arpreq->ip));

      if (!best_rt) {
      /* TODO: didn't find an interface, send an ICMP message type 3 
      code 0, also if there are any errors above */

            return 0;
      }
      struct sr_if* best_if = sr_get_interface(sr, best_rt->interface);

      /* set arp hdr params */
      arp_hdr->ar_hrd = ntohs(1);
      arp_hdr->ar_pro = ntohs(2048);
      arp_hdr->ar_hln = 6;
      arp_hdr->ar_pln = 4;
      arp_hdr->ar_op = ntohs(arp_op_request);

      /* set eth hdr source mac address */ 
      memcpy(eth_hdr->ether_shost, best_if->addr, ETHER_ADDR_LEN);

      /* set arp hdr source mac address */ 
      memcpy(arp_hdr->ar_sha, best_if->addr, ETHER_ADDR_LEN);

      /* set arp hdr dest mac address to  FF:FF:FF:FF:FF:FF */ 
      memcpy(arp_hdr->ar_tha, eth_hdr->ether_dhost, ETHER_ADDR_LEN);

      /* set appropriate IPs */
      arp_hdr->ar_sip = best_if->ip;
      arp_hdr->ar_tip = arpreq->ip;

      /* send packet using correct interface */
      res = 0; 

      
      /* print_hdr_eth(arpbuf);
      print_hdr_arp((uint8_t *) arp_hdr); */
      res = sr_send_packet(sr, arpbuf, minlength,best_if->name );

      if (res != 0) {

            return -1;
      }

      arpreq->sent = now;
      arpreq->times_sent++;  
      return 0;

}

struct sr_rt* find_best_rt(struct sr_rt* routing_table, uint32_t ip) {
      /* Find out which entry in the routing table has 
      the longest prefix match with the 
      destination IP address. */

      struct sr_rt* ip_rt_walker = routing_table;
      
      uint32_t dest, mask,  maxlen = 0;
      struct sr_rt* best_rt = NULL;
      while (ip_rt_walker){
      	dest = ntohl(ip_rt_walker->dest.s_addr);
      	mask = ntohl(ip_rt_walker->mask.s_addr);

          print_addr_ip_int(ntohl(dest));
          print_addr_ip_int(ntohl(ip));
          if ((dest & mask) == (ip & mask)) {

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

            return -1;
      } 


      
      uint8_t * newpacket_for_ip = (uint8_t *) malloc(len);
      memcpy(newpacket_for_ip, packet, len);
      sr_ip_hdr_t *new_iphdr = (sr_ip_hdr_t *)(newpacket_for_ip + sizeof(sr_ethernet_hdr_t));

      /* Decrement the TTL by 1, and recompute the packet 
      checksum over the modified header. */

      /* decrement ttl */
      new_iphdr->ip_ttl--;

      if (new_iphdr->ip_ttl <= 0) {
          /* check ttl, less than zero */
            send_icmp_message(sr,packet, 
                  11,  uint8_t 0);
            return -1;
      }

      /* update checksum. */
      new_iphdr->ip_sum = 0;
      checksum = cksum(new_iphdr, sizeof(*new_iphdr));
      new_iphdr->ip_sum = checksum;
      checksum = cksum(new_iphdr, sizeof(*new_iphdr));

      struct sr_if* assoc_iface = validate_ip(sr->if_list, iphdr->ip_dst);
      if (assoc_iface) {
            /*it's destined to one of our IPs */
            /* ICMP */
            uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
            if (ip_proto == ip_protocol_icmp) { 

                
                  int minlength = sizeof(sr_icmp_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
                  if (len < minlength){
                  
                        return -1;
                  }

                  struct sr_icmp_hdr * icmp_hdr =  (struct sr_icmp_hdr *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                  if(icmp_hdr->icmp_type == 8){
                        /* is an echo request */

                        int res;
                        res = make_echo_request(&newpacket_for_ip, len);

                        if (res == -1){
                              
                              return -1;
                        }
                  }
                  /* end ICMP */
            } else {
                  /* got a udp payload to a rounter interface */
                  int res;
                  res = send_icmp_message(sr, packet, 3,  3);
                  if (res == -1){
                        
                        return -1;
                  }
            }
      }


      /* Find out which entry in the routing table has 
      the longest prefix match with the 
      destination IP address. */
      struct sr_rt* best_rt = find_best_rt(sr->routing_table,  ntohl(new_iphdr->ip_dst));         
      if (!best_rt) {
            /* didn't find an interface, send an ICMP message type 3 
            code 0, also if there are any errors above */
            int res = send_icmp_message(sr, packet, 3,  0);
            if (res == -1){
                 
                  return -1;
            }
            
            return 0;
      }

      /* found an interface */

      struct sr_if * best_iface = sr_get_interface(sr, best_rt->interface);
      if (!best_iface){
           
            return -1;
      }
      struct sr_arpentry * forward_arp_entry = sr_arpcache_lookup(&(sr->cache), best_rt->gw.s_addr);
      
      print_addr_ip_int(ntohl(best_rt->gw.s_addr));
      struct sr_ethernet_hdr * new_ether_hdr = (struct sr_ethernet_hdr * ) newpacket_for_ip; 

      /* ethernet -- update the source address */
      memcpy(new_ether_hdr->ether_shost, best_iface->addr,  ETHER_ADDR_LEN);

      if (forward_arp_entry) {
            /* we have a MAC address */
           

            /* update packet */
            /* ethernet -- set the dest address */
            memcpy(new_ether_hdr->ether_dhost, forward_arp_entry->mac, ETHER_ADDR_LEN);

            /* send packet using correct interface */
            int res = 0; 

            
            print_hdrs(newpacket_for_ip, len);
            res = sr_send_packet(sr, newpacket_for_ip, len, best_rt->interface);

            if (res != 0) {
                 
                  return -1;
            }

            free(forward_arp_entry);
      } else {
            /* we dont have a MAC address, add to arp queue */
            
            struct sr_arpreq * arpreq;
            fprintf(stderr, "queueing ip address: ");
            print_addr_ip_int(ntohl(best_rt->gw.s_addr));
            fprintf(stderr, "on %s\n", best_rt->interface);
            arpreq = sr_arpcache_queuereq(&(sr->cache), best_rt->gw.s_addr, newpacket_for_ip, 
                  len, best_rt->interface );
            if (!arpreq){
                 
                  return -1;
            }
            uint32_t ip, dest;
           
            print_addr_ip_int(ntohl(best_iface->ip));
            ip = ntohl(best_iface->ip);

            dest = ntohl(best_rt->dest.s_addr);
            sr_handle_arp_req(sr, arpreq); 
      } 
      return 0;      
}


struct sr_if* validate_ip(struct sr_if * if_list, uint32_t ip) {

      /* check to see if the target IP belongs to one of our routers */
      struct sr_if* if_walker = if_list;
      while(if_walker){
            print_addr_ip_int(if_walker->ip);
            print_addr_ip_int(ip);
            if (ntohl(if_walker->ip) ==  ntohl(ip)){
                  return if_walker;
            }
            if_walker = if_walker->next;
      }     
      return NULL;
}


int send_arp_response(struct sr_instance * sr, struct sr_if * assoc_iface, uint8_t * packet, unsigned int len) {

      int res; 

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

    
      /*print_hdrs(newpacket, len); */
      res = sr_send_packet(sr, newpacket, len, assoc_iface->name);

      if (res != 0) {
          
            return -1;
      }
      return 0;
}

int handle_arp_reply(struct sr_instance * sr, uint8_t * packet, unsigned int len){

      struct sr_arp_hdr *arp_hdr = (struct sr_arp_hdr *)(packet + sizeof(sr_ethernet_hdr_t));
      struct sr_arpentry *arpentry = sr_arpcache_lookup(&(sr->cache),arp_hdr->ar_sip);

      /* if entry isn't already in cache */
      if (arpentry) {

            return 0;
      }
      struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

      /* if there were requests pending on this IP */
      if(!req){
           
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

      /* check to see if the target IP belongs to one of our routers */
      struct sr_if* assoc_iface = validate_ip(sr->if_list, arp_hdr->ar_tip); 

      if (!assoc_iface){
            /* if its not one of ours, ignore it */
            
            return -1;
      }

      if (arp_op == arp_op_request){ 
            /* this is an incoming request */
           

            res = send_arp_response(sr, assoc_iface,  packet,  len);

            if (res != 0){
                  fprintf(stderr, "bad send_arp_response\n");
                  return -1;
            }


      } else if (arp_op == arp_op_reply) { 
            /* this is an incoming reply */
            

            res = handle_arp_reply(sr, packet, len);
            if (res != 0){
               
                  return -1;
            }
      } else { 
            /* bad arp_op type */
          
            return -1;
      }
      return 0;
}
int generate_echo_request(uint8_t ** packet, unsigned int len){

      uint8_t *newpacket = *packet;
      int icmp_len = len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      uint16_t checksum;
      struct sr_icmp_hdr * icmp_hdr =  (struct sr_icmp_hdr *) (newpacket + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      struct sr_ip_hdr *iphdr = (struct sr_ip_hdr *)(newpacket + sizeof(sr_ethernet_hdr_t));

      /* update icmp info */
      icmp_hdr->icmp_type = 0;
      icmp_hdr->icmp_code = 0;
      icmp_hdr->icmp_sum = 0;
      checksum = cksum(icmp_hdr, icmp_len);
      icmp_hdr->icmp_sum = checksum;

      /* update IP info */

      iphdr->ip_tos = 0;
      iphdr->ip_ttl = 64;

      uint32_t temp = iphdr->ip_src;

      iphdr->ip_src = iphdr->ip_dst;
      iphdr->ip_dst = temp;

      /* update checksum. */
      iphdr->ip_sum = 0;
      checksum = cksum(iphdr, sizeof(*iphdr));
      iphdr->ip_sum = checksum;
      checksum = cksum(iphdr, sizeof(*iphdr));
      if (checksum != 0xffff){
           
            return -1;
      }
      return 0;
}

int make_echo_request(uint8_t ** packet, unsigned int len){

      uint8_t *newpacket = *packet;
      int icmp_len = len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      uint16_t checksum;
      struct sr_icmp_hdr * icmp_hdr =  (struct sr_icmp_hdr *) (newpacket + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(newpacket + sizeof(sr_ethernet_hdr_t));

      /* update icmp info */
      icmp_hdr->icmp_type = 0;
      icmp_hdr->icmp_code = 0;
      icmp_hdr->icmp_sum = 0;
      checksum = cksum(icmp_hdr, icmp_len);
      icmp_hdr->icmp_sum = checksum;

      /* update IP info */

      iphdr->ip_tos = 0;
      iphdr->ip_ttl = 64;

      uint32_t temp = iphdr->ip_src;
      iphdr->ip_src = iphdr->ip_dst;
      iphdr->ip_dst = temp;

      /* update checksum. */
      iphdr->ip_sum = 0;
      checksum = cksum(iphdr, sizeof(*iphdr));
      iphdr->ip_sum = checksum;
      checksum = cksum(iphdr, sizeof(*iphdr));
      if (checksum != 0xffff){
           
            return -1;
      }
      return 0;
}

int send_icmp_message(struct sr_instance * sr, uint8_t * packet, 
      uint8_t icmp_type,  uint8_t icmp_code) {

      int res, size, icmp_len;

      if (icmp_type == 3){
            size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
      } else if (icmp_type == 11) {
            size = sizeof(sr_ethernet_hdr_t) + 2 * sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t) + 8;
      } else {
           
            return -1;

      }
      uint8_t  temp[ETHER_ADDR_LEN]; 
      uint8_t icmp_message[size];
      memcpy(icmp_message, packet, size);

      icmp_len = size - ( sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

      struct sr_ethernet_hdr * ether_hdr = (struct sr_ethernet_hdr * ) icmp_message; 
      struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(icmp_message + sizeof(sr_ethernet_hdr_t));
      struct sr_ip_hdr *old_ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(sr_ethernet_hdr_t));
      struct sr_icmp_hdr * icmp_hdr = (struct sr_icmp_hdr *) (icmp_message + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

      /* swap source and host MAC address */
      memcpy(temp, ether_hdr->ether_dhost, ETHER_ADDR_LEN);
      memcpy(ether_hdr->ether_dhost, ether_hdr->ether_shost, ETHER_ADDR_LEN);
      memcpy(ether_hdr->ether_shost, temp, ETHER_ADDR_LEN);

      if (icmp_type == 11) {
            struct sr_icmp_t3_hdr * t3_hdr = (struct sr_icmp_t3_hdr *) icmp_hdr;
            memcpy(t3_hdr->data, old_ip_hdr, ICMP_DATA_SIZE);
            t3_hdr->next_mtu = 1500;
      }


      /* updte icmp info */
      uint32_t checksum;
      icmp_hdr->icmp_type = icmp_type;
      icmp_hdr->icmp_code = icmp_code;
      icmp_hdr->icmp_sum = 0;
      checksum = cksum(icmp_hdr, icmp_len);
      icmp_hdr->icmp_sum = checksum;

      /* update IP info */
      ip_hdr->ip_tos = 0;
      ip_hdr->ip_ttl = 64;
      uint32_t iptemp;
      iptemp = ip_hdr->ip_src;

      ip_hdr->ip_src = ip_hdr->ip_dst;
      ip_hdr->ip_dst = iptemp;

      /* update ip checksum. */
      ip_hdr->ip_sum = 0;
      checksum = cksum(ip_hdr, sizeof(*ip_hdr));
      ip_hdr->ip_sum = checksum;
      checksum = cksum(ip_hdr, sizeof(*ip_hdr));
      if (checksum != 0xffff){
           
            return -1;
      }

      struct sr_rt* best_rt = find_best_rt(sr->routing_table,  ntohl(ip_hdr->ip_dst));         
      if (!best_rt) {
            
            return -1;
      }

      res = sr_send_packet(sr, icmp_message, size, best_rt->interface);

      if (res != 0) {
            
            return -1;
      }
      return 0;
}
