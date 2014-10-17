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
  /*printf("Recieved packet\n");
  printf("###########################################\n");
  print_hdrs(packet, len);*/

  /* len of packet has to be at least the size of the header */
  if (len > sizeof(sr_ethernet_hdr_t))
  {
    struct sr_if *iface = sr_get_interface(sr, interface);
    /* arp */
    switch(ethertype(packet)){
      case ethertype_arp:
        if (!check_arp(packet, len, iface))
        {
          return;
        }

        handle_arp(sr, packet, iface);
        break;
    /* ip */
      case ethertype_ip: 
        if(!check_ip(packet, len, iface))
        {
          return;
        }

        handle_ip(sr, packet, iface);
        break;

      default:
        printf("this is not arp or ip, exterminate!\n");
        /* what is this? ignore */
    }
  }

}/* end sr_ForwardPacket */

/*-- ARP --*/
 /*
 * Check if an arp request is valid or not
 * Return 1 if valid, 0 otherwise.
 */
int check_arp(uint8_t * packet, unsigned int len, struct sr_if *interface)
{

  /* check to see if packet is large enough for arp + ethernet hdr*/
  if (len < (sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t)))
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

/*
 * Send the arp to the correct function
 */
void handle_arp(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        struct sr_if *interface ) 
{

  /*get the hdr*/
  struct sr_arp_hdr *arp_hdr = get_arp_hdr(packet);
  handle_arp_cache_ops(sr, arp_hdr, interface);

  /* determine if it's a request */
  if (ntohs(arp_hdr->ar_op) == arp_op_request)
  {
    handle_arp_request(sr, arp_hdr, interface);
  }
}
 
/*
 * handle cache operations that arp involves
 */
void handle_arp_cache_ops(struct sr_instance* sr, 
          struct sr_arp_hdr *arp_hdr, 
          struct sr_if *interface) 
{
  /* already an entry here */
  struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, arp_hdr->ar_sip);
  if (entry)
  {
    free(entry);
  } else /* need to add the entry */
  {
    /*printf("inserting into arpcache\n");*/
    struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);  

    /* there are requests waiting for this arp from sip*/
    if(req)
    {
      struct sr_packet *packet = req->packets;

      while(packet)
      {
        struct sr_ip_hdr *ip_hdr = (sr_ip_hdr_t *) packet->buf;
        /*printf("Resending queued requests!!!\n");*/
        encap_and_send(sr, ip_hdr->ip_dst, packet->len, packet->buf, htons(ethertype_ip));
        packet = packet->next;
      } 
      sr_arpreq_destroy(&sr->cache, req);
    }
  }
}

/*
 * create a arp reply and send it
 */
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

  encap_and_send(sr, arp_hdr->ar_sip, sizeof(sr_arp_hdr_t), (uint8_t *) &reply, htons(ethertype_arp));
} 

/*-- ip --*/

/*
 * Check if the ip packet is valid
 * Return 1 if valid, 0 otherwise
 */
int check_ip(uint8_t * packet, unsigned int len, struct sr_if *interface)
{
  
  /* check to see if packet is large enough for ip + ethernet hdr */
  if (len < (sizeof(struct sr_ip_hdr) + sizeof(struct sr_ethernet_hdr)))
  {
    return 0;
  }

  struct sr_ip_hdr *ip_hdr = get_ip_hdr(packet);
  /* check the length of packet against the len in the header */
  if (len != sizeof(struct sr_ethernet_hdr) + ntohs(ip_hdr->ip_len))
  {
    return 0;
  }

  /* checksum */
  uint16_t temp_cksum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  uint16_t calculated_cksum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
  if (calculated_cksum != temp_cksum)
  {
    return 0;
  }

  return 1;
}

/*
 * check if ip should be forwarded or not
 * if not, then send_icmp or drop packet
 */
void handle_ip(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        struct sr_if *interface)
{

  struct sr_ip_hdr *ip_hdr = get_ip_hdr(packet);

  /* Forward or not*/
  if (ip_hdr->ip_dst != interface->ip) 
  {
    /*printf("routing packet\n");*/
    route_packet(sr, packet, interface);
  } else 
  {
   
    /*using a switch for future addition of protocols*/
    switch(ip_hdr->ip_p)
    {
      case ip_protocol_icmp:
      {
        struct sr_icmp_hdr *icmp_hdr;
        icmp_hdr = get_icmp_hdr(packet);
        if (icmp_hdr->icmp_type != icmp_echo_request)
        {
          return;
        }
        
        uint16_t temp_cksum = icmp_hdr->icmp_sum;
        icmp_hdr->icmp_sum = 0;
        uint16_t calculated_cksum = cksum((uint8_t *) icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl * 4);
        if (temp_cksum != calculated_cksum)
        {
          return;
        }

        /*printf("sending icmp_ehco_reply!\n");*/
        /* all good, send reply*/
        send_icmp(sr, (uint8_t *) ip_hdr, icmp_echo_reply, 0);   
        break;
      }
      default:
        /*send port unreachable */
        printf("port unreachable");
    }

  }
}

/*
 * decrement ttl and route ip to the correct addr. 
 * if the ttl expire, send time exceeded icmp.
 */
void route_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        struct sr_if *interface)
{
    struct sr_ip_hdr *ip_hdr = get_ip_hdr(packet);

    /* decrement ttl */
    uint8_t ttl = ip_hdr->ip_ttl;
    ttl--;
    if (ttl == 0)
    { 
      /*send ICMP Time exceeded */
      /*printf("Time exceeded, sending ICMP back\n");*/
      send_icmp(sr, (uint8_t *) ip_hdr, icmp_time_exceeded, 0);
      return;
    }
    
    unsigned int len = ntohs(ip_hdr->ip_len);
    
    /* redo the checksums */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
    
    /* make a new packet since the packet is lent */   
    uint8_t *new_packet = malloc(len);
    memcpy(new_packet, ip_hdr, len);
    encap_and_send(sr, ip_hdr->ip_dst, len, new_packet, htons(ethertype_ip));
    
    free(new_packet);
}


/*-- sending --*/
/*
 * call icmp handlers depending on type of the icmp
 */
void send_icmp(struct sr_instance* sr,
          uint8_t* packet,
          uint8_t type,
          uint8_t code)
{
  switch(type){
    case icmp_unreachable:
    case icmp_time_exceeded:
    {
      struct sr_ip_hdr *ip_hdr = (sr_ip_hdr_t *) packet;

      /* get the interface to see where to send this back to */
      struct sr_rt *rt_entry = sr_get_longest_match(sr, ip_hdr->ip_src);
      if (rt_entry == 0) 
      {
        /* no idea where to send this back to??*/
        return;
      }

      struct sr_if *iface = sr_get_interface(sr, rt_entry->interface);

      create_icmp_t3(sr, (struct sr_ip_hdr *) packet, type, code, iface);
      break;
    }
    case icmp_echo_reply:
      create_icmp(sr, (struct sr_ip_hdr *) packet, type, code);
  }
}

/*
 * create and send a t3 icmp
 */
void create_icmp_t3(struct sr_instance *sr, struct sr_ip_hdr *packet, uint8_t type, uint8_t code, struct sr_if *interface)
{
  /* dont use pointer here, dont have to deal with malloc */
  struct sr_icmp_t3_hdr *icmp_hdr;
  struct sr_ip_hdr *ip_hdr;
  unsigned int len = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  
  uint8_t *new_packet;
  new_packet = malloc(len);
  icmp_hdr = (sr_icmp_t3_hdr_t *) ((uint8_t *)new_packet + sizeof(sr_ip_hdr_t));
  ip_hdr = (sr_ip_hdr_t *) new_packet;

  icmp_hdr->icmp_type = type; 
  icmp_hdr->icmp_code = code;
  icmp_hdr->icmp_sum = 0;
  memcpy((uint8_t *)icmp_hdr + sizeof(sr_icmp_t3_hdr_t) - ICMP_DATA_SIZE , packet, ICMP_DATA_SIZE);

  /* ip_hdr */
  ip_hdr->ip_hl = 5;
  ip_hdr->ip_v = 4;
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_id = packet->ip_id;
  ip_hdr->ip_off = htons(IP_DF);
  ip_hdr->ip_ttl = DEFAULT_TTL;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->ip_dst = packet->ip_src;
  ip_hdr->ip_src = interface->ip;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_len = htons(len);  
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  icmp_hdr->icmp_sum = cksum(new_packet + sizeof(sr_ip_hdr_t), sizeof(sr_icmp_t3_hdr_t));

  encap_and_send(sr, ip_hdr->ip_dst, len, new_packet, htons(ethertype_ip));
  free(new_packet);
}

/*
 * create an regular icmp response and send the icmp. 
 */
void create_icmp(struct sr_instance *sr, struct sr_ip_hdr *packet, uint8_t type, uint8_t code)
{
  /*copy the packet*/
  struct sr_ip_hdr *ip_hdr = packet;  
  struct sr_icmp_hdr *icmp_hdr = (sr_icmp_hdr_t * )((uint8_t *)(ip_hdr) + (ip_hdr->ip_hl * 4));

  icmp_hdr->icmp_type = type; 
  icmp_hdr->icmp_code = code;
  icmp_hdr->icmp_sum = 0;
  uint16_t calculated_cksum = cksum((uint8_t *) icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl * 4);
  icmp_hdr->icmp_sum = calculated_cksum;
  /*print_hdr_icmp((uint8_t *)icmp_hdr);*/

  uint32_t dst = ip_hdr->ip_src;
  ip_hdr->ip_src = ip_hdr->ip_dst;
  ip_hdr->ip_dst = dst;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

  unsigned int len = ntohs(ip_hdr->ip_len);
  uint8_t *new_packet;
  new_packet = malloc(len);
  memcpy(new_packet, ip_hdr, len);

  encap_and_send(sr, dst, len, new_packet, htons(ethertype_ip));
  free(new_packet);
}

/*
 * encapulate the packet with ethernet header and send the packet
 */
void encap_and_send(struct sr_instance* sr,
          uint32_t target_ip,  
          unsigned int len,
          uint8_t* packet,
          uint16_t ethertype)
{
  struct sr_rt *rt_entry = sr_get_longest_match(sr, target_ip);
  if (rt_entry == 0) {
    /* send icmp? */
    send_icmp(sr, packet, icmp_unreachable, icmp_port_unreachable);
    /*printf("failed to find target IP: ");
    print_addr_ip_int(target_ip);*/
    return;
  }

  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, rt_entry->gw.s_addr);
  if (arp_entry) {
    unsigned int packet_length = len + sizeof(sr_ethernet_hdr_t);
    uint8_t *new_packet = malloc(packet_length);
    struct sr_ethernet_hdr *ethernet_hdr = malloc(sizeof(sr_ethernet_hdr_t));    
    struct sr_if *interface = sr_get_interface(sr, rt_entry->interface);

    /*populate ethernet header*/
    ethernet_hdr->ether_type = ethertype; 
    memcpy(ethernet_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
    memcpy(ethernet_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);

    /* copy the 2 piece into the new_packet */
    memcpy(new_packet, ethernet_hdr, sizeof(sr_ethernet_hdr_t));
    memcpy(new_packet + sizeof(sr_ethernet_hdr_t), packet, len);
    /* printf("sending packet\n");
    printf("###########################################\n");
    print_hdrs(new_packet, packet_length);*/

    sr_send_packet(sr, new_packet, len + sizeof(struct sr_ethernet_hdr), rt_entry->interface);
    
    free(new_packet);
    free(ethernet_hdr);
    if (arp_entry)
    {
      free(arp_entry);
    }

  } else {
    /*printf("adding to req queue\n");
    print_hdr_ip(packet);*/
    sr_arpcache_queuereq(&sr->cache, rt_entry->gw.s_addr, packet, len, rt_entry->interface);
  }
}

/*
 * broadcast an arq reply to all ports
 */
void broadcast_arq(struct sr_instance* sr, struct sr_arp_hdr arp_hdr, struct sr_if *interface)
{
  struct sr_rt *rt_entry = sr_get_longest_match(sr, arp_hdr.ar_tip);

  if(rt_entry == 0){
    /*printf("should fail if found none");*/
    return;
  }
  /* build the packet */
  uint8_t *packet;
  struct sr_ethernet_hdr ethernet_hdr;
  unsigned int len = sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t);
  ethernet_hdr.ether_type = htons(ethertype_arp);
  memset(ethernet_hdr.ether_dhost, 255, ETHER_ADDR_LEN);
  memcpy(ethernet_hdr.ether_shost, interface->addr, ETHER_ADDR_LEN);

  packet = malloc(len);
  memcpy(packet, &ethernet_hdr, sizeof(sr_ethernet_hdr_t));
  memcpy(packet + sizeof(sr_ethernet_hdr_t), &arp_hdr, sizeof(sr_arp_hdr_t));

  /* print_hdr_arp((uint8_t * ) arp_hdr); 
  printf("boardcasting arp packet\n");
  printf("###########################################\n");
  print_hdrs(packet, len);*/

  sr_send_packet(sr, packet, len, rt_entry->interface);
  free(packet);
}