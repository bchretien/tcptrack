#ifndef SocketPair_H
#define SocketPair_H

#include "IPAddress.h"
#include "TCPHeader.h"

// a SocketPair is the combination of source/dest ports and addrs.
// it is used as a fingerprint to identify connections.

class SocketPair
{
public:
	SocketPair( IPAddress &naddra, portnum_t nporta, 
			IPAddress &naddrb, portnum_t nportb );
	SocketPair( const SocketPair & );
	~SocketPair();
	bool operator==( const SocketPair & ) const;
	bool operator!=( const SocketPair & ) const;
	const IPAddress & addrA() const { return *m_pAddrA; };
	const IPAddress & addrB() const { return *m_pAddrB; };
	portnum_t portA() const { return m_portA; };
	portnum_t portB() const { return m_portB; };
	uint32_t hash() const;

private:
	IPAddress *m_pAddrA;
	IPAddress *m_pAddrB;
	portnum_t m_portA;
	portnum_t m_portB;
};

#endif
