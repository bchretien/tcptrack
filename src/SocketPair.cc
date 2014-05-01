#include <unistd.h>
#include <assert.h>
#include "IPAddress.h"
#include "SocketPair.h"

SocketPair::SocketPair( IPAddress &naddrA, portnum_t nm_portA,  
		IPAddress &naddrB, portnum_t nm_portB )
: m_portA(nm_portA), m_portB(nm_portB)
{
	m_pAddrA = naddrA.Clone();
	m_pAddrB = naddrB.Clone();
}

	SocketPair::SocketPair( const SocketPair &orig )
: m_portA(orig.m_portA), m_portB(orig.m_portB)
{
	m_pAddrA = orig.m_pAddrA->Clone();
	m_pAddrB = orig.m_pAddrB->Clone();
}

SocketPair::~SocketPair()
{
	delete m_pAddrA;
	delete m_pAddrB;
}

// a socketpair is equal to another SocketPair if their src/dst addrs & ports
// are the same, OR if they are just the opposite (ie, if it were for a 
// packet heading in the opposite direction).
// this is so packets heading in either direction will match the same 
// connection.
bool SocketPair::operator==( const SocketPair &sp ) const
{
	if( *(sp.m_pAddrA) == *(m_pAddrA)  &&  *(sp.m_pAddrB) == *(m_pAddrB) 
			&& sp.m_portA == m_portA && sp.m_portB == m_portB )
	{
		return true;
	} 
	else if( *(sp.m_pAddrA) == *(m_pAddrB)  &&  *(sp.m_pAddrB) == *(m_pAddrA) 
			&& sp.m_portA == m_portB && sp.m_portB == m_portA )
	{
		return true;
	}
	else
		return false;
}

bool SocketPair::operator!=( const SocketPair &sp ) const
{
	return !( sp==*this );
}

uint32_t SocketPair::hash() const
{
	uint32_t hash = 0;

	assert( m_portB > 0 );
	hash = m_pAddrA->hash() % m_portB;

	assert( m_portA > 0 );
	hash += m_pAddrB->hash() % m_portA;

	return hash;
}

