#ifndef SR_HELPER_H
#define SR_HELPER_H


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

struct sr_rt* find_best_rt(struct sr_rt* routing_table, uint32_t ip) ;
int handle_ip_packet(struct sr_instance * sr, uint8_t * packet, unsigned int len );
struct sr_rt* validate_ip(struct sr_rt * routing_table, uint32_t ip) ;
int send_arp_response(struct sr_instance * sr, struct sr_rt * assoc_iface_rt, uint8_t * packet, unsigned int len);
int handle_arp_reply(struct sr_instance * sr, uint8_t * packet, unsigned int len);
int handle_arp_packet(struct sr_instance * sr, uint8_t * packet, unsigned int len );
int sr_handle_arp_req (struct sr_instance * sr, struct sr_arpreq * arpreq, uint8_t * eth_source, int len,
	uint32_t sender_ip, uint32_t dest_ip, char * iface);
int make_echo_request(uint8_t ** packet, unsigned int len);
#endif