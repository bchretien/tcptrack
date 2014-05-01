#include <typeinfo>
#include <cassert>
#include <typeinfo>
#include <unistd.h>
#include <sys/time.h>
#include "TCPPacket.h"
#include "TCPCapture.h"
#include "util.h"

TCPCapture::TCPCapture( TCPPacket *tcp_packet,
		struct timeval nts )
{
	m_packet = tcp_packet;
	m_ts = nts;
}

TCPCapture::TCPCapture( const TCPCapture & orig )
{
	m_packet = new TCPPacket( *orig.m_packet );
	m_ts = orig.m_ts;
}

TCPCapture::~TCPCapture()
{
	if( m_packet != NULL)
		delete m_packet;
}

TCPPacket & TCPCapture::GetPacket() const
{
	return *m_packet;
}

