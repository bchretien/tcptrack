#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <assert.h>

#include "IPv4Address.h"
#include "util.h"

// this function is used for C functions that need a C-style string.
char * IPv4Address::ptr() const
{
	static char ascii[16]; // 12 for octets, 3 dots, 1 null

	unsigned int iaddr = ntohl(m_addr.s_addr);
	int oc1 = (iaddr & 0xFF000000)/16777216;
	int oc2 = (iaddr & 0x00FF0000)/65536;
	int oc3 = (iaddr & 0x0000FF00)/256;
	int oc4 = (iaddr & 0x000000FF);

	sprintf(ascii,"%d.%d.%d.%d",oc1,oc2,oc3,oc4);

	return ascii;	
}

bool IPv4Address::operator==( const IPAddress & addr ) const
{
	if ( addr.GetType() != GetType())
		return false;

	const IPv4Address *ipv4_addr = dynamic_cast<const IPv4Address*>(&addr);
	assert( ipv4_addr != NULL);

	return ipv4_addr->m_addr.s_addr == m_addr.s_addr;
}

uint32_t IPv4Address::hash() const
{
	return m_addr.s_addr;
}

IPAddress* IPv4Address::Clone() const
{
	return new IPv4Address(m_addr);
}

