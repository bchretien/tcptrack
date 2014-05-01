#ifndef TCPPACKET_H
#define TCPPACKET_H 1
#define __FAVOR_BSD 1

#include <netinet/in.h> // needed 
#include "IPAddress.h"
#include "TCPHeader.h"
#include "SocketPair.h"

class TCPPacket
{
public:
	/* stuff to do in constructor:
	 *  ensure data_len >= ip header len field
	 *  ensure version is 4
	 *  ensure total len >= ip header len
	 *  verify checksum
	 */
	TCPPacket( const u_char *data, unsigned int data_len );
	TCPPacket( const TCPPacket &orig );
	~TCPPacket();
	unsigned int totalLen() const;
	unsigned long len() const { return total_len; };
	unsigned int payloadLen() const;
	IPAddress & srcAddr() const;
	IPAddress & dstAddr() const;
	TCPHeader & tcp() const { return *m_tcp_header; }
	SocketPair & sockpair() const { return *m_socketpair; }
	static TCPPacket * newTCPPacket( const u_char *data, unsigned int data_len );

private:
	unsigned int total_len;
	unsigned short header_len;

	// these are pointers because the IPAddress class is not modifiable
	// after initialization. The constructor of this class can not 
	// immediately set them.
	IPAddress *m_src;
	IPAddress *m_dst;

	TCPHeader *m_tcp_header;
	SocketPair *m_socketpair;
};


#endif
