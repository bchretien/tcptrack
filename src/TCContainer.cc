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
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include "TCPConnection.h"
#include "Collector.h"
#include "TCContainer.h"
#include "SortedIterator.h"
#include "defs.h"
#include "util.h"
#include "Guesser.h"
//#include "IPv4Packet.h"
#include "SocketPair.h"
#include "TCPTrack.h"
#include "GenericError.h"

extern TCPTrack *app;

TCContainer::TCContainer()
{
	//
	// Start up maintenence thread
	//
	state=TSTATE_IDLE;

	pthread_attr_t attr;

	pthread_mutex_init( &conlist_lock, NULL );
	pthread_mutex_init( &state_mutex, NULL );

	if( pthread_attr_init( &attr ) != 0 )
		throw GenericError("pthread_attr_init() failed");

	pthread_attr_setstacksize( &attr, SS_TCC );

	if( pthread_create(&maint_thread_tid,&attr,maint_thread_func,this) != 0 )
		throw GenericError("pthread_create() failed.");

	state=TSTATE_RUNNING;
	purgeflag=true;
}

// remove closed connections?
void TCContainer::purge( bool npurgeflag )
{
	purgeflag=npurgeflag;
}

// shut down the maintenence thread. prepare to delete this object.
void TCContainer::stop()
{
	pthread_mutex_lock(&state_mutex);
	if( state!=TSTATE_RUNNING ) 
	{
		pthread_mutex_unlock(&state_mutex);
		return;
	}
	state=TSTATE_STOPPING;
	pthread_mutex_unlock(&state_mutex);

	// maint thread will notice that state is no longer RUNNING and
	// will exit. just wait for it...
	pthread_join(maint_thread_tid,NULL);	

	state=TSTATE_DONE;
}

TCContainer::~TCContainer()
{
	stop();
	for( tccmap::iterator i=conhash2.begin(); i!=conhash2.end(); )
	{
		TCPConnection *rm = (*i).second;
		tccmap::iterator tmp_i = i;
		i++;
		conhash2.erase(tmp_i);
		collector.collect(rm);
	} 
}

SortedIterator * TCContainer::getSortedIteratorPtr()
{
	return new SortedIterator(this);
}

// the sniffer (or PacketBuffer rather) hands us packets via this method.
bool TCContainer::processPacket( TCPCapture &p )
{
	lock();
	bool found = false;

	// a SocketPair is the combination of source/dest ports and addrs.
	// it is used as a fingerprint to identify connections.
	SocketPair sp( p.GetPacket().srcAddr(), p.GetPacket().tcp().srcPort(), 
			p.GetPacket().dstAddr(), p.GetPacket().tcp().dstPort() );

	// iterate over all packets that match this SocketPair and see if they'll
	// take the packet.
	pair<tccmap::const_iterator, tccmap::const_iterator> pr = conhash2.equal_range(sp);
	for( tccmap::const_iterator i = pr.first; i!=pr.second; i++ )
	{
		TCPConnection *ic = (*i).second;
		if( ic->acceptPacket( p ) )
		{
			found=true;
		}
	}

	// is this a new connection?
	if( found==false && (p.GetPacket().tcp().syn()) && !(p.GetPacket().tcp().ack()) )
	{
		TCPConnection *newcon = new TCPConnection( p );
		found = true;
		conhash2.insert(tccmap::value_type(sp,newcon));
	}

	// a stray packet. Feed it to guesser. Guesser tries to learn about
	// connections that we're not aware of.
	if( !found && app->detect )
	{
		TCPConnection *newcon = guesser.addPacket(p);
		if( newcon != NULL ) 
			conhash2.insert(tccmap::value_type(sp,newcon));
	}

	unlock();

	return found;
}

unsigned int TCContainer::numConnections()
{
	return conhash2.size();
}

// the maintenence thread recalculates averages and stuff.
void TCContainer::maint_thread_run()
{
	while( state==TSTATE_RUNNING || state==TSTATE_IDLE )
	{
		struct timespec ts;
		if( app->fastmode )
		{
			ts.tv_sec=0;
			ts.tv_nsec=FASTMODE_INTERVAL;
		}
		else
		{
			ts.tv_sec=1;
			ts.tv_nsec=0;
		}
		nanosleep(&ts,NULL);

		lock();

		int numitems = 0;
		for( tccmap::iterator i=conhash2.begin(); i!=conhash2.end(); )
		{
			TCPConnection *ic=(*i).second;
			numitems++;
			ic->recalcAvg();

			// remove closed or stale connections.
			if( purgeflag==true )
			{
				if(    ( ic->isFinished() && ic->getIdleSeconds() > app->remto ) 
						|| ( ic->getState()==TCP_STATE_SYN_SYNACK && ic->getIdleSeconds()>SYN_SYNACK_WAIT )
						|| ( ic->getState()==TCP_STATE_FIN_FINACK && ic->getIdleSeconds()>FIN_FINACK_WAIT )
					)
				{
					TCPConnection *rm = ic;
					tccmap::iterator tmp_i = i;
					i++;
					conhash2.erase(tmp_i);
					collector.collect(rm);
				}
				else
					i++;
			} 
			else
			{
				i++;
			}
		} 

		unlock();		
	}
}


void TCContainer::lock()
{
	pthread_mutex_lock(&conlist_lock);
}

void TCContainer::unlock()
{
	pthread_mutex_unlock(&conlist_lock);
}


///////////////////

void *maint_thread_func( void * arg )
{
	TCContainer *c = (TCContainer *) arg;
	c->maint_thread_run();
	return NULL;
}

