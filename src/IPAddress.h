/**
 * Abstract base class,
 * to be used everywhere instead of IPv4Address/IPv6Address
 **/
#ifndef IPADDRESS_H
#define IPADDRESS_H 1

#include <stdint.h>
#include <ostream>

class IPAddress
{
public:
  IPAddress() { }
  virtual ~IPAddress() { }

	virtual int GetType() const = 0;
	virtual bool operator==( const IPAddress & ) const = 0;
	virtual bool operator!=( const IPAddress & addr ) const { return !operator!=(addr); }
	virtual char * ptr() const = 0;
	virtual uint32_t hash() const = 0;
	virtual IPAddress* Clone() const = 0;
};

std::ostream& operator<<( std::ostream &out, const IPAddress &ip );

#endif

