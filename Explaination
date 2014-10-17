Explaination

This file contain a brief explaination on what I have done.

For this assignment I looked at the execution flow of the router and thought that it was most logically to split up the assignment into 3 parts:


ARP:

This was the first thing I implemented. I followed the instruction given in the arpcache.h, and created handlers for arp for reply and requests in router.c. Arpcache follows the psuedo code. 

#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_

IP:

I moved onto getting ip to work, because I needed this to work inorder to start testing. To do this, I followed the same structure as arp and funneled different ip type into different functions. The 2 main functions in this case is the route_packet, and encap_and_send

encap_and_send is a function that is needed by almost anything that need to send out a packet. It handles encapulating the packet with ethernet header, and then passing the new packet out using sr_send_packet

#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_

ICMP:

lastly, icmp have 2 main functions. 1 to handle a icmp_hdr, and another to handle type 3 icmp_hdr. the first function is only used to handle echo reply, so I just changed the packet it self and sent it back out. 

The latter, takes cares of the icmps that needs the larger header. 

To make working with icmp easier, I created enums to numerate the icmp types and codes. 