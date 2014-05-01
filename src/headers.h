/* 
 *  Ths code in this file is part of tcptrack. For more information see
 *    http://www.rhythm.cx/~steve/devel/tcptrack
 *
 *     Copyright (C) Steve Benson - 2003
 *
 *  tcptrack is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your
 *  option) any later version.
 *   
 *  tcptrack is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *   
 *  You should have received a copy of the GNU General Public License
 *  along with GNU Make; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA. 
 *  
 */
#ifndef HEADERS_H
#define HEADERS_H 1

#define __FAVOR_BSD 1

#include <unistd.h> // needed on BSD
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include "config.h"

#ifndef BYTE_ORDER
#ifdef WORDS_BIGENDIAN
#define BYTE_ORDER  BIG_ENDIAN
#else
#define BYTE_ORDER  LITTLE_ENDIAN
#endif // ifdef WORDS_BIGENDIAN
#endif // ifndef BYTE_ORDER
            
#define IP_HEADER_LEN 20
#define IP6_HEADER_LEN 40
#define TCP_HEADER_LEN 20
#define ENET_HEADER_LEN 14
#define SLL_HEADER_LEN 16
#define VLAN_HEADER_LEN 4

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100
#endif

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    #ifdef WORDS_BIGENDIAN
    u_int ip_v:4, /* version */
    ip_hl:4; /* header length */
    #else
    u_int ip_hl:4, /* header length */
    ip_v:4; /* version */
    #endif
    u_char ip_tos; /* type of service */
    u_short ip_len; /* total length */
    u_short ip_id; /* identification */
    u_short ip_off; /* fragment offset field */
    #define IP_RF 0x8000 /* reserved fragment flag */
    #define IP_DF 0x4000 /* dont fragment flag */
    #define IP_MF 0x2000 /* more fragments flag */
    #define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
    u_char ip_ttl; /* time to live */
    u_char ip_p; /* protocol */
    u_short ip_sum; /* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};

struct sniff_ip6 {
  uint32_t ip_v6:4; /* version */
  uint32_t ip_class:8; /* traffic class */
  uint32_t ip_flow:20; /* flow label */
  uint32_t ip_len:16;  /* payload length */
  uint32_t ip_next:8;  /* next header */
  uint32_t ip_hop:8;   /* hop limit */
  struct in6_addr ip_src; /* src address */
  struct in6_addr ip_dst; /* dst address */
};

/* TCP header */
struct sniff_tcp {
    u_short th_sport; /* source port */
    u_short th_dport; /* destination port */
    tcp_seq th_seq; /* sequence number */
    tcp_seq th_ack; /* acknowledgement number */
    #ifdef WORDS_BIGENDIAN
    u_int th_off:4, /* data offset */
    th_x2:4; /* (unused) */
    #else
    u_int th_x2:4, /* (unused) */
    th_off:4; /* data offset */
    #endif
    u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
};

#endif
