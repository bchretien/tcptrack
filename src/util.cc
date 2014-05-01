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
#include "util.h"
#include <stdio.h>
#include <cstring>
#include "headers.h"
#ifdef HAVE_HASH_MAP
# include <hash_map>
#elif HAVE_EXT_HASH_MAP
# include <ext/hash_map>
#endif
#include <string.h>

/*
 * getnlp takes a raw packet (with link level header) sniffed from an 
 * interface whose type is dlt (values for dlt are the DLT_* macros in
 * net/bpf.h).
 * It returns a struct nlp, which contains a pointer to the beginning 
 * of the network layer protocol (in *p) and a value to identify the network
 * layer protocol
 */
struct nlp *getnlp( const u_char *p, int dlt, const pcap_pkthdr *pcap )
{
	struct nlp *n = (struct nlp *) malloc( sizeof(struct nlp) );

	n->p=NULL;
	n->ts = pcap->ts;
	n->len = 0;
	int vlan_frame = 0;

	if( dlt==DLT_EN10MB )
	{
		if( pcap->caplen < ENET_HEADER_LEN+IP_HEADER_LEN )
		{
			free(n);
			return NULL;
		}

		const struct sniff_ethernet *ethernet;
		ethernet = (struct sniff_ethernet*)(p);
		vlan_frame = ( ntohs(ethernet->ether_type) == ETHERTYPE_VLAN );
		uint16_t ether_type;

		if( vlan_frame )
			ether_type = ntohs(*((uint16_t *)(p + ENET_HEADER_LEN + VLAN_HEADER_LEN - 2)));
		else
			ether_type = ntohs(ethernet->ether_type);

		if( ether_type == ETHERTYPE_IP || ether_type == ETHERTYPE_IPV6 )
		{
			n->len = pcap->caplen-ENET_HEADER_LEN-(vlan_frame ? VLAN_HEADER_LEN : 0);
			n->p = (u_char *) malloc( sizeof(u_char) * n->len );
			memcpy( (void *)n->p, (void *)(p+ENET_HEADER_LEN+(vlan_frame ? VLAN_HEADER_LEN : 0)), n->len);
		}
		else
		{
			free(n);
			return NULL;
		}
	}
	else if( dlt==DLT_LINUX_SLL )
	{
		if( pcap->caplen < SLL_HEADER_LEN+IP_HEADER_LEN )
		{
			free(n);
			return NULL;
		}

		n->len = pcap->caplen-SLL_HEADER_LEN;
		n->p = (u_char *) malloc( sizeof(u_char) * n->len );
		memcpy( (void *)n->p, (void *)(p+SLL_HEADER_LEN), n->len);
	}
	else if( dlt==DLT_RAW || dlt==DLT_NULL )
	{
		if( pcap->caplen < IP_HEADER_LEN )
		{
			free(n);
			return NULL;
		}

		n->len = pcap->caplen;
		n->p = (u_char *) malloc( sizeof(u_char) * n->len );
		memcpy( (void *)n->p, (void *)(p), n->len);
	}

	return n;
}

/* This function performs all kinds of tests on captured packet data to 
 * ensure that it is a valid packet of the given network layer protocol.
 * data is the raw packet, data_len is its length
 * proto is one of the NLP_* values. currently only NLP_IPV4 works.
 * This needs to be run early upon packet reception. Other code assumes it 
 * has. If they detect a bad packet, assertions will fail.
 */
// TODO: this should be split up into smaller functions
bool checknlp( struct nlp *n )
{
	struct sniff_ip *ip = (struct sniff_ip *)n->p;

	//TODO: Improve this / split in two functions (IPv6/IPv4)
	if( ip->ip_v == 6 )
	{
		if( n->len < IP6_HEADER_LEN + TCP_HEADER_LEN )
		{
			return false;
		}

		struct sniff_ip6 *ip6 = (struct sniff_ip6 *)n->p;

		if( ip6->ip_next != IPPROTO_TCP ) 
		{
			return false;
		}

		struct sniff_tcp *tcp = (struct sniff_tcp *) (n->p + IP6_HEADER_LEN);

		if( tcp->th_off < 5 ) // tcp header is at least 20 bytes long.
		{
			return false;
		}

		if( tcp->th_sport == 0 )
			return false;

		if( tcp->th_dport == 0 )
			return false;

		return true;
	}

	unsigned int ip_header_len = ip->ip_hl * 4;

	// not enough data to do anything with this...
	// we're only interested in IPv4 TCP Packets
	if( n->len < ip_header_len + TCP_HEADER_LEN )
		return false;
	
	if( ip->ip_v != 4 )
		return false;

	if( ntohs(ip->ip_len) < ip_header_len + TCP_HEADER_LEN ) 
		return false;

	if( ip->ip_hl < 5 ) 
		return false;

	if( ip->ip_p != IPPROTO_TCP ) 
		return false;

	struct sniff_tcp *tcp = (struct sniff_tcp *) (n->p + ip_header_len);

	if( tcp->th_off < 5 ) // tcp header is at least 20 bytes long.
		return false;
		
	if( tcp->th_sport == 0 )
		return false;

	if( tcp->th_dport == 0 )
		return false;

	return true;
}
