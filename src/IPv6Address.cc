#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <netinet/in.h>
#include "IPv6Address.h"
#include "util.h"

uint16_t IPv6Address::GetShort( int index ) const
{
	assert(index >= 0);
	assert(index < 8);

	//return ntohs(m_addr.in6_u.u6_addr16[index]);
	return ntohs(m_addr.s6_addr16[index]);
}

// this function is used for C functions that need a C-style string.
char * IPv6Address::ptr() const
{
	static char ascii[INET6_ADDRSTRLEN];

	snprintf(ascii, 42, "[%x:%x:%x:%x:%x:%x:%x:%x]", 
			GetShort(0),
			GetShort(1),
			GetShort(2),
			GetShort(3),
			GetShort(4),
			GetShort(5),
			GetShort(6),
			GetShort(7));

	return ascii;
}

bool IPv6Address::operator==( const IPAddress & addr ) const
{
	if ( addr.GetType() != GetType())
		return false;

	const IPv6Address *ipv6_addr = dynamic_cast<const IPv6Address*>(&addr);
	assert( ipv6_addr != NULL);

	return memcmp(&ipv6_addr->m_addr, &m_addr, 16) == 0;
}

uint32_t IPv6Address::hash() const
{
	// The last 4 bytes of the IPv6 address are a good enough hash for now
	//return m_addr.in6_u.u6_addr32[3];
	return m_addr.s6_addr16[3];
}

IPAddress* IPv6Address::Clone() const
{
	return new IPv6Address(m_addr);
}

