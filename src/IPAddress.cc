#include "IPAddress.h"

std::ostream& operator<<( std::ostream &out, const IPAddress &ip )
{
	out << ip.ptr();
	return out;
}

