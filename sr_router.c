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
#include <string.h> 
#include <stdlib.h>

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
    
    /* Add initialization code here! */

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

  printf("*** -> Received packet of length %d \n",len);
  /* fill in code here */

  /* len of packet has to be at least the size of the header */
  if (len > sizeof(struct sr_ethernet_hdr))
  {
    struct sr_if *iface = sr_get_interface(sr, interface);
    /* arp */
    if(ethertype(packet) == ethertype_arp)
    {
      if (!check_arp(packet, len, iface))
      {
        return;
      }

      handle_arp(sr, packet, iface);

    /* ip */
    } else 
    {
      if(!check_ip(packet, len, iface))
      {
        return;
      }

      handle_ip(sr, packet, iface);
    
    }
  }

}/* end sr_ForwardPacket */

/*-- ARP --*/
 /*
 * check the arp to see if it is valid, if it is return 1
 * else return 0
 */
int check_arp(uint8_t * packet, unsigned int len, struct sr_if *interface)
{

  /* check to see if packet is large enough for arp + ethernet hdr*/
  if (len < (sizeof(struct sr_arp_hdr) + sizeof(struct sr_ethernet_hdr)))
  {
    return 0;
  }

  /* check the hardware address format */
  struct sr_arp_hdr *arp_hdr = get_arp_hdr(packet);
  if (ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet)
  {
    return 0;
  }

  /*no checksum because this is arp, ip already checked by sr_arp_req_not_for_us*/
  return 1;
}


void handle_arp(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        struct sr_if *interface ) 
{

  /*get the hdr*/
  struct sr_arp_hdr *arp_hdr = get_arp_hdr(packet);

  /* determine if it's a request or a reply */
  if (ntohs(arp_hdr->ar_op) == arp_op_request)
  {
    printf("request\n");
    print_hdr_arp(packet);
    handle_arp_request(sr, arp_hdr, interface);
    
  } else 
  {
    printf("reply\n");
    handle_arp_reply(sr, arp_hdr, interface);
  }
}

void handle_arp_request(struct sr_instance* sr, 
          struct sr_arp_hdr *arp_hdr, 
          struct sr_if *interface
          )
{
  /* create reply header and send back to who requested it*/
  struct sr_arp_hdr reply;
  reply.ar_hrd = htons(arp_hrd_ethernet);
  reply.ar_pro = htons(ethertype_ip); /*ip addresses*/
  reply.ar_hln = ETHER_ADDR_LEN;
  reply.ar_pln = sizeof(uint32_t);
  reply.ar_op = htons(arp_op_reply);
  reply.ar_sip = interface->ip;
  reply.ar_tip = arp_hdr->ar_sip;

  memcpy(reply.ar_sha, interface->addr, ETHER_ADDR_LEN);
  memcpy(reply.ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);

  broadcast_arq(sr, reply, interface);
} 
 
void handle_arp_reply(struct sr_instance* sr, 
          struct sr_arp_hdr *arp_hdr, 
          struct sr_if *interface) 
{

  struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, arp_hdr->ar_sip);
  if (entry)
  {
    free(entry);
    return;
  }

  printf("inserting into arpcache");
  struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);  

  /* there are requests waiting for this arp*/
  if(req)
  {
      struct sr_packet *packet = req->packets;
      while(packet)
      {
        encap_and_send(sr, packet->iface, arp_hdr->ar_tip, packet->len, packet->buf);
        packet = packet->next;
      } 
      sr_arpreq_destroy(&sr->cache, req);
  }
}

void broadcast_arq(struct sr_instance* sr, struct sr_arp_hdr arp_hdr, struct sr_if *interface)
{
  struct sr_rt *rt_entry = sr_get_longest_match(sr, arp_hdr.ar_sip);

  if(rt_entry == 0){
    /*send icmp?*/
    printf("should fail if found none");
    return;
  }
  /* build the packet */
  uint8_t *packet;
  struct sr_ethernet_hdr eth_hdr;
  unsigned int len = sizeof(struct sr_arp_hdr) + sizeof(struct sr_ethernet_hdr);
  memset(eth_hdr.ether_dhost, 255, ETHER_ADDR_LEN);
  memcpy(eth_hdr.ether_shost, interface->addr, ETHER_ADDR_LEN);

  packet = malloc(len);
  memcpy(packet, &eth_hdr, sizeof(struct sr_ethernet_hdr));
  memcpy(packet + sizeof(struct sr_ethernet_hdr), &arp_hdr, sizeof(struct sr_arp_hdr));

  print_hdr_arp(packet);
  sr_send_packet(sr, packet, len,  rt_entry->interface);
  free(packet);
}

/*-- ip --*/
int check_ip(uint8_t * packet, unsigned int len, struct sr_if *interface){
  
  /* check to see if packet is large enough for ip + ethernet hdr */
  if (len < (sizeof(struct sr_ip_hdr) + sizeof(struct sr_ethernet_hdr)))
  {
    return 0;
  }

  /* checksum */
  struct sr_ip_hdr *ip_hdr = get_ip_hdr(packet);
  uint16_t temp_cksum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  uint16_t calculated_cksum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
  if (calculated_cksum != temp_cksum)
  {
    return 0;
  }

  /* check the length of packet against the len in the header */
  if (len != sizeof(struct sr_ethernet_hdr) + ntohs(ip_hdr->ip_len))
  {
    return 0;
  }
    
  return 1;
}

void handle_ip(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        struct sr_if *interface)
{

  struct sr_ip_hdr *ip_hdr = get_ip_hdr(packet);

  /* Forward or not*/
  if (ip_hdr->ip_dst != interface->ip) 
  {
    route_packet(sr, packet, interface);
  } else 
  {
   
    /*using a switch for future addition of protocols*/
    switch(ip_hdr->ip_p)
    {
      case ip_protocol_icmp:
        
      break;

      default:
        /*send port unreachable */
    }

  }
}

void route_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        struct sr_if *interface)
{
    struct sr_ip_hdr *ip_hdr = get_ip_hdr(packet);

    if (ip_hdr->ip_ttl <= 1)
    { 
      /*TODO: */
      /*send ICMP Time exceeded */
    } else {
      /* decrement it, if it's >= 2 */
      ip_hdr->ip_ttl--;
    } 
    
    unsigned int len = ntohs(ip_hdr->ip_len);
    
    /* redo the checksums */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
    
    /* make a new packet since the packet is lent */   
    uint8_t new_packet = malloc(len);
    memcpy(new_packet, ip_hdr, len);
    encap_and_send(sr, interface, ip_hdr->ip_dst, len, new_packet);
    
    free(new_packet);
}


/*-- sending --*/

void encap_and_send(struct sr_instance* sr,
          char* interface, 
          uint32_t target_ip,  
          unsigned int len,
          uint8_t* packet)
{}