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
#define _BSD_SOURCE 1
#define _REENTRANT
#include <queue>
#include <time.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <assert.h>
#include "headers.h"
#include "TCContainer.h"
#include "PacketBuffer.h"
#include "defs.h"
#include "TCPPacket.h"
#include "TCPCapture.h"
#include "GenericError.h"

PacketBuffer::PacketBuffer()
{
	inq = &pq1;
	outq = &pq2;
	c=NULL;
	pthread_initted=false;

	pthread_mutex_init( &c_lock, NULL );
	pthread_mutex_init( &inq_lock, NULL );
	pthread_cond_init( &inq_flag, NULL );
}

void PacketBuffer::init()
{
	//
	// Start up maintenence thread
	//
	pthread_attr_t attr;
	if( pthread_attr_init( &attr ) != 0 )
		throw GenericError("pthread_attr_init() failed");

	// TODO: there is no man page for this call on linux. Not sure what it
	// may return. On some systems it may not be supported at all 
	// (should return ENOSYS). Should be safe to ignore return val.
	pthread_attr_setstacksize( &attr, SS_PB );

	if( pthread_create(&maint_thread_tid,&attr,pbmaint_thread_func,this) != 0 )
		throw GenericError("pthread_create() returned an error");

	pthread_initted=true;
}

void PacketBuffer::dest( TCContainer *nc )
{
	assert( pthread_mutex_lock(&c_lock) == 0 );
	c=nc;
	assert( pthread_mutex_unlock(&c_lock) == 0 );
}

PacketBuffer::~PacketBuffer()
{
	if( pthread_initted )
	{
		// if pthread_cancel returns non-zero, this indicates that
		// maint_thread_tid is not valid. It may have stopped because of
		// an exception. Don't bother joining in that case.
		if( pthread_cancel(maint_thread_tid) == 0 )
			pthread_join(maint_thread_tid,NULL);
	}
}

void PacketBuffer::pushPacket( struct nlp *p )
{
	assert(p!=NULL);
	assert( pthread_mutex_lock(&c_lock) == 0 );

	// if no destination has been set, drop the packet.
	if( c==NULL )
	{
		assert( pthread_mutex_unlock(&c_lock) == 0 );
		return;
	}

	assert( pthread_mutex_lock(&inq_lock) == 0 );
	inq->push(p);
	// wake up the maint thread if it is sleeping...
	assert( pthread_cond_signal(&inq_flag) == 0 );
	assert( pthread_mutex_unlock(&inq_lock) == 0 );

	assert( pthread_mutex_unlock(&c_lock) == 0 );
}

void PacketBuffer::maint_thread_run()
{
	struct nlp *p;

	while(1)
	{
		// see if inq is empty.
		//  if empty: wait on a condition variable set by pushPacket
		//  if not: process inq as usual.

		assert( pthread_mutex_lock(&inq_lock) == 0 );

		// if the input queue is empty, sleep until something is deposited.
		if( inq->empty() )
			pthread_cond_wait(&inq_flag,&inq_lock);

		// swap in & out queues
		// this allows the input queue to be unlocked ASAP so the Sniffer
		// won't be delayed for too long.
		if( inq == &pq1 )
		{
			inq = &pq2;
			outq = &pq1;
		}
		else
		{
			inq = &pq1;
			outq = &pq2;
		}
		assert( pthread_mutex_unlock(&inq_lock) == 0 );

		// process outq
		// outq doesn't need locks because this (pb maint thread) is the
		//  only thread that should ever access it.
		p=NULL;
		int qlen=0;
		while( ! outq->empty() )
		{
			++qlen;
			p=NULL;
			p=outq->front();

			assert( pthread_mutex_lock(&c_lock) == 0 );
			if( c != NULL )
			{
				// The sniffer only hands us TCP packets
				TCPPacket *tcp_packet = TCPPacket::newTCPPacket(p->p, p->len);
				assert ( tcp_packet != NULL );

				TCPCapture c2 (tcp_packet, p->ts);
				c->processPacket( c2 );
			}
			assert( pthread_mutex_unlock(&c_lock) == 0 );

			free(p->p);
			free(p);
			outq->pop();
		}
	}

}

////////////////////////

void *pbmaint_thread_func( void *arg )
{
	PacketBuffer *pb = (PacketBuffer *) arg;
	pb->maint_thread_run();
	return NULL;
}
