#ifndef IPV6ADDRESS_H
#define IPV6ADDRESS_H 1

#include <netinet/in.h>
#include <iostream>
#include "headers.h"

#include "IPAddress.h"

class IPv6Address : public IPAddress
{
public:
	IPv6Address( const struct in6_addr &addr ) { m_addr = addr; }
	IPv6Address( IPv6Address &addr ) { m_addr = addr.m_addr; }

	virtual int GetType() const { return 6; }
	virtual bool operator==( const IPAddress & ) const;
	virtual char * ptr() const;

	virtual uint32_t hash() const;
	virtual IPAddress* Clone() const;

private:
	uint16_t GetShort( int index ) const;
	struct in6_addr m_addr;
};

#endif
