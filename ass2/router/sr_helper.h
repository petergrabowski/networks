#ifndef SR_HELPER_H
#define SR_HELPER_H


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* take a packet buffer, change the packet into an echo response */
int make_echo_request(uint8_t ** packet, unsigned int len);

/* given an IP address, find the best routing table entry for it */
struct sr_rt* find_best_rt(struct sr_rt* routing_table, uint32_t ip) ;

/* respond to an ARP or IP packet, or detect an error and handle appropriately*/
int handle_ip_packet(struct sr_instance * sr, uint8_t * packet, 
                     unsigned int len );

/* given an IP, test whether it belongs to one of the routers ifaces */
struct sr_if* validate_ip(struct sr_if * iface_list, uint32_t ip) ;

/* respond to a given ARP request for one of the routers ifaces */
int send_arp_response(struct sr_instance * sr, struct sr_if * assoc_if, uint8_t * packet, unsigned int len);

/* process an ARP reply -- add IP/MAC pair to arp cache */
int handle_arp_reply(struct sr_instance * sr, uint8_t * packet,
                     unsigned int len);

/* handle an incoming ARP packet (req or resp), or detect errors */
int handle_arp_packet(struct sr_instance * sr, uint8_t * packet, 
                      unsigned int len );

/* process an incoming ARP req */
int sr_handle_arp_req (struct sr_instance * sr, struct sr_arpreq * arpreq);

/* send icmp messages of type icmp_type and code icmp_code */
int send_icmp_message(struct sr_instance * sr, uint8_t * packet, 
      uint8_t icmp_type,  uint8_t icmp_code);

#endif

