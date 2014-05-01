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
#ifndef TCPCONNECTION_H
#define TCPCONNECTION_H 1

#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <list>
#include "util.h"
#include "TCPPacket.h"
#include "TCPHeader.h"
#include "TCPCapture.h"
#include "SocketPair.h"

#define TCP_STATE_SYN_SYNACK    1 // initial SYN sent, waiting for SYN ACK
#define TCP_STATE_SYNACK_ACK 2 // SYN&ACK response sent, waiting for ACK
#define TCP_STATE_UP    3 // SYNACK response sent
#define TCP_STATE_FIN_FINACK 4
#define TCP_STATE_CLOSED 5
#define TCP_STATE_RESET 6

using namespace std;

class TCPConnection
{
public:
	// constructor, which needs the initial packet that created this
	// connection, or any packet that is going from client->server.
	// See comments in Guesser.cc for an explanation...
	TCPConnection( TCPCapture &p );
	~TCPConnection();

	// returns true if the given addresses/ports are relevant to this
	// connection.
	bool match(IPAddress &sa, IPAddress &da, portnum_t sp, portnum_t dp);

	// see if packet p is relevant to this connection. 
	// if it is, true will be returned and this object's internal 
	// state will be changed to relect the new packet.
	bool acceptPacket( TCPCapture &p );

	// get the addresses/ports which are the endpoints for this
	// connection.
	IPAddress & srcAddr();
	portnum_t srcPort();
	IPAddress & dstAddr();
	portnum_t dstPort();

	// returns one of the TCP_STATE_* values reflecting the connection's
	// state.
	int getState();

	// returns true if this connection is closed and no more traffic
	// is expected for it.
	bool isFinished();

	// timestamp of last packet sent either way
	time_t getLastPktTimestamp();
	// number of seconds since last packet sent either way
	time_t getIdleSeconds(); 

	// called to recalculate averages and perform any other internal 
	// updates to counters and stuff.
	// should be called at least once a second.
	// if fastMode is enabled, calling it more freqently will keep 
	// counters closer to real time.
	// if fastMode is not enabled, there's no point in calling it more
	// than once a second, but it won't hurt.
	void recalcAvg();

	// this implements an "activity light" that works just like the
	// activity LEDs on a modem.  returns true if a packet was sent
	// since the last time it was called.
	bool activityToggle();

	// number of packets sent either way in total for this connection
	int getPacketCount();

	// number of payload bytes sent either way in total for this connection
	long getPayloadByteCount();

	// average number of packets per second this connection is doing
	int getPacketsPerSecond();

	// average number of packets per second this connection is doing
	// this counts only the packet's actual tcp payload, no headers
	unsigned int getPayloadBytesPerSecond();

	// average number of bytes per second this connection is doing
	// this counts the tcp and ip headers (but not link layer header)
	int getAllBytesPerSecond();

	// returns a key that fairly uniquely identifies this connection
	// used for hashing purposes
	//int getKey();

	// a SocketPair is two IPAddresses and two TCP port numbers.
	// The pair of each represents this connections src/dst addrs & ports.
	SocketPair & getEndpoints();
private:
	bool fastMode();
	void purgeAvgStack();
	void fastRecalcAvg();
	void slowRecalcAvg();
	void updateCountersForPacket( TCPCapture &p );

	unsigned long finack_from_dst;
	unsigned long finack_from_src;
	bool recvd_finack_from_src;
	bool recvd_finack_from_dst;

	SocketPair *endpts;

	portnum_t srcport; // client port
	portnum_t dstport; // server port
	IPAddress *srcaddr; // client addr
	IPAddress *dstaddr; // server addr

	int state;

	time_t last_pkt_ts;
	int packet_count;

	long payload_byte_count;

	bool activity_toggle;

	list<struct avgstat> avgstack;	
	unsigned int fm_bps; // bytes per second
	unsigned int fm_pps; // packets per second

	// per-second stats
	time_t this_second;
	unsigned int packets_this_second;
	unsigned int payload_bytes_this_second; // payload only
	unsigned int all_bytes_this_second; // ip hdr + tcp hdr + payload
	unsigned int packets_last_second;
	unsigned int payload_bytes_last_second; // payload only
	unsigned int all_bytes_last_second; // ip hdr + tcp hdr + payload

};

#endif
