#include <iostream>
#include "TCPCapture.h"
#include "Guesser.h"

Guesser::Guesser()
{
}

Guesser::~Guesser()
{
	for( pktmap::iterator i=hash.begin(); i!=hash.end(); )
	{
		TCPCapture *cp = (*i).second;
		pktmap::iterator tmp_i = i;
		i++;
		hash.erase(tmp_i);
		delete cp;
	}
}

TCPConnection * Guesser::addPacket( TCPCapture &p )
{
	// TODO: there should be a thread or something that periodically
	// checks hash for the age of the packets it contains and removes 
	// old stuff.

	// TCP Packets with the following flags set will not trigger the
	// detection of a new connection.
	if( p.GetPacket().tcp().syn() )
		return NULL;
	if( p.GetPacket().tcp().ece() )
		return NULL;
	if( p.GetPacket().tcp().fin() || p.GetPacket().tcp().rst() )
	{
		hash.erase(p.GetPacket().sockpair());
		return NULL;
	}


	if( hash[p.GetPacket().sockpair()]==NULL )
	{
		// no packets received yet for this connection
		TCPCapture *cp = new TCPCapture(p);
		hash[cp->GetPacket().sockpair()]=cp;


		return NULL;
	}
	else
	{
		// already received a packet for this connection.
		// replace the old with the new. (remove later)
		// return a connection.

		TCPCapture *ocp = hash[p.GetPacket().sockpair()];
		hash.erase(p.GetPacket().sockpair());


		if(    ( ocp->GetPacket().srcAddr() == p.GetPacket().dstAddr() )
				&& ( ocp->GetPacket().tcp().srcPort() == p.GetPacket().tcp().dstPort() ) 
				&& ( p.timestamp().tv_sec-ocp->timestamp().tv_sec < 60 ) )
		{
			TCPConnection *nc;

			// Currently a TCPConnection expects to be built from a packet
			// that is going from the client to the server. This is because
			// the client initiates the connection and TCPConnection
			// was originally coded to only accept the initial SYN packet
			// to its constructor. At some point this logic may be
			// moved into the TCPConnection constructor.

			// crude way to guess at which end is the client:
			// whichever end has the lowest port number.
			// TODO: can this cli/server guessing be made more intelligent?
			if( p.GetPacket().tcp().srcPort() > p.GetPacket().tcp().dstPort() )
			{
				// this packet might be the one we saw that went from
				// client->server.
				nc=new TCPConnection(p);
			}
			else
			{
				// if not, maybe it was this other packet.
				nc=new TCPConnection(*ocp);
			}

			delete ocp;
			return nc;
		}
		else
		{
			hash[ocp->GetPacket().sockpair()] = new TCPCapture(p);
			delete ocp;
			return NULL;
		}
	}

	return NULL;
}
