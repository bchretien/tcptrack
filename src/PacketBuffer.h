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

#ifndef PACKETBUFFER_H
#define PACKETBUFFER_H
#include <queue>
#include "TCContainer.h"

class PacketBuffer
{
public:
	PacketBuffer();
	~PacketBuffer();
	
	// performs more constructor-like activity, but exceptions can
	// be thrown from within here.
	void init();
	
	// tells PacketBuffer where to send its packets. 
	// if NULL, PB will drop all new packets.
	void dest( TCContainer *nc = NULL );

	// add a new packet to this buffer for processing. 
	void pushPacket( struct nlp *p );

	// do not call. only called from pbmaint_thread_func.
	// the pb processor thread runs in here.
	void maint_thread_run();
	
private:
	// was the thread successfully launched?
	bool pthread_initted;

	// these are the queues that hold the packets we are given.
	std::queue<struct nlp *> pq1;
	std::queue<struct nlp *> pq2;
	// these point to either pq1 or pq2. They never both point to the 
	// same pqX queue.
	std::queue<struct nlp *> *inq;
	std::queue<struct nlp *> *outq;
	// mutexes for the input queue (above).
	// none needed for the output queue since that's only touched 
	// by the maint thread.
	pthread_mutex_t inq_lock;

	// when the input queue is empty, the maint thread goes to sleep.
	// when a packet is added, this cond var is set to wake it up.
	pthread_cond_t inq_flag;
	
	// packets are sent here.
	TCContainer *c;
	pthread_mutex_t c_lock; // mutex for the above.
	
	pthread_t maint_thread_tid;
};

void *pbmaint_thread_func( void * );

#endif
