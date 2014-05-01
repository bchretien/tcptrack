#include <cassert>
#include <iostream>
#include <unistd.h>
#include "IPv4Address.h"
#include "IPv6Address.h"
#include "TCPPacket.h"
#include "headers.h"
#include "util.h"

TCPPacket::TCPPacket( const u_char *data, unsigned int data_len )
{
	struct sniff_ip *ip = (struct sniff_ip *)data;

	if( ip->ip_v == 4)
	{
		// make sure that the various length fields are long enough to contain
		// an IPv4 header (at least 20 bytes).
		assert( data_len >= 20 ); 
		assert( ntohs(ip->ip_len) >= 20 ); // TODO: is this right?
		assert( ip->ip_hl >= 5 );

		total_len=ntohs(ip->ip_len);

		m_src = new IPv4Address(ip->ip_src);
		m_dst = new IPv4Address(ip->ip_dst);
		header_len=ip->ip_hl*4;
	}
	else if( ip->ip_v == 6 )
	{
		struct sniff_ip6 *ip6 = (struct sniff_ip6 *)data;

		total_len = htons(ip6->ip_len);
		header_len = IP6_HEADER_LEN;
		m_src = new IPv6Address(ip6->ip_src);
		m_dst = new IPv6Address(ip6->ip_dst);
	}
	else
	{
		// Unknown protocol. The sniffer should have protected us.
		assert( false );
	}

	m_tcp_header = new TCPHeader(data + header_len, data_len - header_len);  
	m_socketpair = new SocketPair(*m_src, m_tcp_header->srcPort(), *m_dst, m_tcp_header->dstPort());
}

TCPPacket::TCPPacket( const TCPPacket &orig )
{
	m_src = orig.srcAddr().Clone();
	m_dst = orig.dstAddr().Clone();
	total_len = orig.total_len;
	header_len = orig.header_len;
	m_tcp_header = new TCPHeader( *orig.m_tcp_header );
	m_socketpair = new SocketPair( *orig.m_socketpair );
}

TCPPacket::~TCPPacket()
{
	delete m_src;
	delete m_dst;
	delete m_tcp_header;
	delete m_socketpair;
}

unsigned int TCPPacket::totalLen() const { return total_len; }
IPAddress & TCPPacket::srcAddr() const { return *m_src; }
IPAddress & TCPPacket::dstAddr() const { return *m_dst; }

std::ostream & operator<<( std::ostream &out, const TCPPacket &ip )
{
	out << "IP: ";
	out << "src=" << ip.srcAddr();
	out << " dst=" << ip.dstAddr();
	out << " len=" << ip.totalLen();
	return out;
}

unsigned int TCPPacket::payloadLen() const
{
	return total_len-header_len;
}

TCPPacket* TCPPacket::newTCPPacket( const u_char *data, unsigned int data_len )
{
	struct sniff_ip *ip = (struct sniff_ip *)data;

	if( ip->ip_v == 4 && ip->ip_p != IPPROTO_TCP ) return NULL;

	if( ip->ip_v == 6 )
	{
		struct sniff_ip6 *ip = (struct sniff_ip6 *)data;

		if( ip->ip_next != IPPROTO_TCP ) return NULL;
	}

	return new TCPPacket(data,data_len);
}

