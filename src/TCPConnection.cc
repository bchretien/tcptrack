/* 
 *  Ths code in this file is part of tcptrack. For more information see
 *    http://www.rhythm.cx/~steve/devel/tcptrack
 *
 *     Copyright (C) Steve Benson - 2003
 *
 *  tcptrack is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your
 *  option) any later version.
 *   
 *  tcptrack is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *   
 *  You should have received a copy of the GNU General Public License
 *  along with GNU Make; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA. 
 *  
 */
#define _DEFAULT_SOURCE 1
#define _BSD_SOURCE 1
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_PCAP_PCAP_H
#include <pcap/pcap.h>
#elif HAVE_PCAP_H
#include <pcap.h>
#endif
#include <time.h>
#include "headers.h"
#include "TCPConnection.h"
#include "util.h"
#include "TCPTrack.h"
#include "TCPPacket.h"
#include "SocketPair.h"

extern TCPTrack *app;

TCPConnection::~TCPConnection()
{
	delete srcaddr;
	delete dstaddr;
	delete endpts;
}

bool TCPConnection::fastMode()
{
	return app->fastmode;
}

bool TCPConnection::isFinished()
{
	if( state == TCP_STATE_CLOSED || state == TCP_STATE_RESET )
		return true;
	return false;
}

IPAddress & TCPConnection::srcAddr()
{
	return *srcaddr;
}

portnum_t TCPConnection::srcPort()
{
	return srcport;
}

IPAddress & TCPConnection::dstAddr()
{
	return *dstaddr;
}

portnum_t TCPConnection::dstPort()
{
	return dstport;
}

int TCPConnection::getPacketCount()
{
	return packet_count;
}

long TCPConnection::getPayloadByteCount()
{
	return payload_byte_count;
}

int TCPConnection::getState()
{
	return state;
}

TCPConnection::TCPConnection( TCPCapture &p ) 
{
	srcaddr = p.GetPacket().srcAddr().Clone();
	dstaddr = p.GetPacket().dstAddr().Clone();
	srcport = p.GetPacket().tcp().srcPort();
	dstport = p.GetPacket().tcp().dstPort();

	packet_count=1;
	if( p.GetPacket().tcp().syn() )
		state = TCP_STATE_SYN_SYNACK;
	else
		state = TCP_STATE_UP;

	// init per-second stats counters
	this_second = time(0);
	packets_this_second = 1;

	payload_bytes_this_second = p.GetPacket().payloadLen()-p.GetPacket().tcp().headerLen();
	all_bytes_this_second = p.GetPacket().totalLen();
	payload_bytes_last_second = 0;
	all_bytes_last_second = 0;

	payload_byte_count = p.GetPacket().payloadLen() - p.GetPacket().tcp().headerLen();

	last_pkt_ts = time(NULL);
	activity_toggle=false;

	/*
		 if( fastMode() )
		 {
		 struct avgstat s;
		 s.ts = p->pcap.ts;
		 s.size = ntohs(p->ip->ip_len)-(IP_HEADER_LEN+TCP_HEADER_LEN);
		 avgstack.push_front(s);
		 }
		 */
	fm_bps=0;

	finack_from_dst=0;
	finack_from_src=0;
	recvd_finack_from_src=false;
	recvd_finack_from_dst=false;

	endpts = new SocketPair( *srcaddr, srcport, *dstaddr, dstport);
}

void TCPConnection::purgeAvgStack()
{
	struct timeval now;
	gettimeofday(&now,NULL);
	list<struct avgstat>::iterator i;
	for( i=avgstack.begin(); i!=avgstack.end(); i++ )
	{
		struct avgstat cur = *i;
		struct timeval top = cur.ts;
		if( top.tv_sec <= now.tv_sec-2 )
		{
			avgstack.erase(i,avgstack.end());
			break;
		}
	}
}

void TCPConnection::fastRecalcAvg()
{
	struct timeval now;
	gettimeofday(&now,NULL);
	unsigned int bytes_past_second=0;
	unsigned int packets_past_second=0;
	purgeAvgStack();

	list<struct avgstat>::iterator i;
	for( i=avgstack.begin(); i!=avgstack.end(); i++ )
	{
		struct avgstat cur = *i;
		struct timeval top = cur.ts;
		if( top.tv_sec == now.tv_sec )
			if( top.tv_usec <= now.tv_usec )
			{
				bytes_past_second += cur.size;
				packets_past_second++;
			}
		if( top.tv_sec == now.tv_sec-1 )
			if( top.tv_usec >= now.tv_usec )
			{
				bytes_past_second += cur.size;
				packets_past_second++;
			}
	}
	fm_bps=bytes_past_second; 
	fm_pps=packets_past_second;
}

void TCPConnection::slowRecalcAvg()
{
	if( this_second != time(0) )
	{
		packets_last_second = packets_this_second;
		payload_bytes_last_second = payload_bytes_this_second;
		all_bytes_last_second = all_bytes_this_second;

		this_second = time(0);
		packets_this_second = 0;
		payload_bytes_this_second = 0;
		all_bytes_this_second = 0;
	}
}

// recalculate packets/bytes per second counters
// should be called once per second
void TCPConnection::recalcAvg()
{
	if( fastMode() )
		fastRecalcAvg();
	else
		slowRecalcAvg();
}

time_t TCPConnection::getLastPktTimestamp()
{
	return last_pkt_ts;
}

bool TCPConnection::match( IPAddress &sa, IPAddress &da, portnum_t sp, portnum_t dp )
{
	if( ! (*srcaddr == sa) ) 
		return false;
	if( !( *dstaddr == da) )
		return false;
	if( dp != dstport  ||  sp != srcport )
		return false;

	return true;
}

time_t TCPConnection::getIdleSeconds()
{
	return time(NULL) - getLastPktTimestamp();
}

void TCPConnection::updateCountersForPacket( TCPCapture &p )
{
	if( fastMode() )
	{
		struct avgstat s;
		s.ts = p.timestamp();
		s.size = p.GetPacket().payloadLen() - p.GetPacket().tcp().headerLen();
		avgstack.push_front(s);
	}
	else 
	{
		if( this_second != time(0) )
		{
			packets_last_second = packets_this_second;
			payload_bytes_last_second = payload_bytes_this_second;
			all_bytes_last_second = all_bytes_this_second;

			this_second = time(0);
			packets_this_second = 1;
			payload_bytes_this_second = p.GetPacket().payloadLen() - p.GetPacket().tcp().headerLen();
			all_bytes_this_second = p.GetPacket().totalLen();
		}
		else
		{
			packets_this_second++;
			payload_bytes_this_second += p.GetPacket().payloadLen() - p.GetPacket().tcp().headerLen();
			all_bytes_this_second += p.GetPacket().totalLen();
		}

		payload_byte_count += p.GetPacket().payloadLen() - p.GetPacket().tcp().headerLen();
	}
}

bool TCPConnection::acceptPacket( TCPCapture &cap )
{
	TCPPacket *p = &(cap.GetPacket());
	unsigned int payloadlen = p->payloadLen() - p->tcp().headerLen();

	if( state == TCP_STATE_CLOSED ) 
		return false;


	if(  match(p->srcAddr(), p->dstAddr(), p->tcp().srcPort(), p->tcp().dstPort()) 
			|| match(p->dstAddr(), p->srcAddr(), p->tcp().dstPort(), p->tcp().srcPort()) )
	{
		++packet_count;
		activity_toggle=true;

		// recalculate packets/bytes per second counters
		updateCountersForPacket(cap);

		if( p->tcp().fin() )
		{
			// if this is a fin going from cli->srv
			// expect an appropriate ack from server
			if( p->srcAddr() == *srcaddr ) 
			{
				if( payloadlen==0 )
					finack_from_dst = p->tcp().getSeq()+1;
				else
					finack_from_dst = p->tcp().getSeq()+payloadlen+1;
				recvd_finack_from_dst=false;
			}
			if( p->srcAddr() == *dstaddr ) 
			{
				if( payloadlen==0 )
					finack_from_src = p->tcp().getSeq()+1;
				else
					finack_from_src = p->tcp().getSeq()+payloadlen+1;
				recvd_finack_from_src=false;
			}
		}

		if( state == TCP_STATE_SYNACK_ACK )
		{
			if( p->tcp().ack() ) 
				state = TCP_STATE_UP; // connection up
		}
		else if( state == TCP_STATE_SYN_SYNACK )
		{
			if( p->tcp().syn() && p->tcp().ack() )
				state = TCP_STATE_SYNACK_ACK; // SYN|ACK sent, awaiting ACK
		}
		else if( state == TCP_STATE_UP )
		{
			if( p->tcp().fin() )
				state = TCP_STATE_FIN_FINACK; // FIN sent, awaiting FIN|ACK
		}
		else if( state == TCP_STATE_FIN_FINACK )
		{
			if( p->tcp().ack() )
			{
				if( p->srcAddr() == *srcaddr ) 
					if( p->tcp().getAck() == finack_from_src )
						recvd_finack_from_src=true;
				if( p->srcAddr() == *dstaddr ) 
					if( p->tcp().getAck() == finack_from_dst )
						recvd_finack_from_dst=true;
				if( recvd_finack_from_src && recvd_finack_from_dst )
					state=TCP_STATE_CLOSED;
			}
		}
		if( p->tcp().rst() )
			state = TCP_STATE_RESET;

		last_pkt_ts = time(NULL);

		return true;
	}
	// packet rejected because this connection is closed.
	return false;
}

int TCPConnection::getPacketsPerSecond()
{
	if( fastMode() ) 
		return fm_pps;
	else 
		return packets_last_second;
}

unsigned int TCPConnection::getPayloadBytesPerSecond()
{
	if( fastMode() )
		return fm_bps;
	else
		return payload_bytes_last_second;
}

int TCPConnection::getAllBytesPerSecond()
{
	if( fastMode() ) 
	{
		// TODO: at some point when this handles ipv6, this alg will
		// have to be changed.
		return fm_pps*(IP_HEADER_LEN+TCP_HEADER_LEN)+fm_bps;
	}
	else
		return all_bytes_last_second;
}

// this implements an activity "light" for this connection... should work
// just like the send/receive light on a modem. 
// needs to be called frequently (at least once per second) to be of any use.
bool TCPConnection::activityToggle()
{
	bool r = activity_toggle;
	activity_toggle=false;
	return r;
}

SocketPair & TCPConnection::getEndpoints()
{
	return *endpts;
}
