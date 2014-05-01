#include <iostream>
#include <assert.h>
#include <unistd.h>
#include "TCPHeader.h"
#include "headers.h"

TCPHeader::TCPHeader( const u_char *data, unsigned int data_len )
{
	struct sniff_tcp *tcp = (struct sniff_tcp *)data;

	assert( tcp->th_off >= 5 ); // tcp header is at least 20 bytes long.

	src = ntohs(tcp->th_sport);
	dst = ntohs(tcp->th_dport);
	seqn=ntohl(tcp->th_seq);
	ackn=ntohl(tcp->th_ack);
	flags=tcp->th_flags;

	header_len=tcp->th_off*4;
}

TCPHeader::TCPHeader( TCPHeader & orig )
{
	seqn = orig.seqn;
	ackn = orig.ackn;
	src = orig.src;
	dst = orig.dst;
	flags = orig.flags;
	header_len = orig.header_len;
}

bool TCPHeader::fin() const { return flags&FIN; }
bool TCPHeader::syn() const { return flags&SYN; }
bool TCPHeader::rst() const { return flags&RST; }
bool TCPHeader::psh() const { return flags&PSH; }
bool TCPHeader::ack() const { return flags&ACK; }
bool TCPHeader::urg() const { return flags&URG; }
bool TCPHeader::ece() const { return flags&ECE; }
bool TCPHeader::cwr() const { return flags&CWR; }

seq_t TCPHeader::getSeq() const { return seqn; }
seq_t TCPHeader::getAck() const { return ackn; }
portnum_t TCPHeader::srcPort() const { return src; }
portnum_t TCPHeader::dstPort() const { return dst; }

std::ostream & operator<<( std::ostream &out, const TCPHeader &tcp )
{
	out << "ports=" << tcp.srcPort() << "->" << tcp.dstPort();

	out << " seq=" << tcp.getSeq();
	out << " ack=" << tcp.getAck();

	out << " flags=";

	if( tcp.fin() ) 
		out << " FIN";
	if( tcp.syn() )
		out << " SYN";
	if( tcp.rst() ) 
		out << " RST";
	if( tcp.psh() ) 
		out << " PSH";
	if( tcp.ack() ) 
		out << " ACK";
	if( tcp.urg() ) 
		out << " URG";
	if( tcp.ece() ) 
		out << " ECE";
	if( tcp.cwr() ) 
		out << " CWR";

	return out;
}
