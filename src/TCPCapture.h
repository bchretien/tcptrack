#ifndef TCPCAPTURE_H
#define TCPCAPTURE_H 1

#include <sys/time.h>
#include "TCPPacket.h"

/* An TCPCapture is a packet captured off the wire that is known to be
 * an TCP packet
 */
class TCPCapture
{
public:
	TCPCapture( TCPPacket* tcp_packet,
			struct timeval nts );
	TCPCapture( const TCPCapture &orig );
	~TCPCapture();
	TCPPacket & GetPacket() const;
	struct timeval timestamp() const { return m_ts; };
private:
	TCPPacket *m_packet;	
	struct timeval m_ts;
};

#endif
