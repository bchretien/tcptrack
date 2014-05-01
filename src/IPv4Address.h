#ifndef IPV4ADDRESS_H
#define IPV4ADDRESS_H 1

#include <netinet/in.h>
#include <iostream>
#include "headers.h"

#include "IPAddress.h"

class IPv4Address : public IPAddress
{
public:
	IPv4Address(struct in_addr addr) { m_addr = addr; }
	IPv4Address(IPv4Address &addr) { m_addr = addr.m_addr; }

	virtual int GetType() const { return 4; }
	virtual bool operator==( const IPAddress & ) const;
	virtual char * ptr() const;

	virtual uint32_t hash() const;
	virtual IPAddress* Clone() const;

private:
	struct in_addr m_addr;
};

#endif
