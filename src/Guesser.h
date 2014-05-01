#ifndef GUESSER_H
#define GUESSER_H 1

#include "../config.h"
#ifdef HAVE_HASH_MAP
#include <hash_map>
#elif HAVE_EXT_HASH_MAP
#include <ext/hash_map>
#endif
#include "SocketPair.h"
#include "util.h"
#include "TCPConnection.h"
#include "TCPCapture.h"

#ifdef GNU_CXX_NS
using namespace __gnu_cxx;
#endif

class GEqFunc : public unary_function<SocketPair,bool>
{
public:
	bool operator()( const SocketPair &sp1, const SocketPair & sp2 )
	{
		if( sp1==sp2 )
			return true;
		else
			return false;
	}
};

class GHashFunc : public unary_function<SocketPair, uint32_t>
{
public:
	uint32_t operator()(const SocketPair &sp) const
	{
		return sp.hash();
	}
};

typedef hash_map<SocketPair, TCPCapture *,GHashFunc, GEqFunc> pktmap;

/* Guesser implements the 'detect connections that started before
 * tcptrack was started' functionality.
 * The Guesser takes TCP packets that don't belong to any known 
 * connection and stores them. As it is fed more stray packets, it may
 * detect a TCP connection on the network.
 */

class Guesser
{
public:
	Guesser();
	~Guesser();

	// feed Guesser a stray packet. If it results in a connection
	// detected, it will be returned. If no new connections, NULL 
	// is returned.
	TCPConnection * addPacket( TCPCapture &p );
private:
	// stray packets that we're keeping track of are stored here.
	// indexed by src/dst addrs and ports.
	pktmap hash;
};

#endif
