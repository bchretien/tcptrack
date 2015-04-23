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
#include "../config.h"
#define _DEFAULT_SOURCE 1
#define _BSD_SOURCE 1
#define _REENTRANT
#include <pthread.h>
#include <cassert>
#ifdef HAVE_PCAP_PCAP_H
#include <pcap/pcap.h>
#elif HAVE_PCAP_H
#include <pcap.h>
#endif
#include "PacketBuffer.h"
#include "Sniffer.h"
#include "defs.h"
#include "GenericError.h"
#include "AppError.h"
#include "PcapError.h"
#include "TCPTrack.h"

extern TCPTrack *app;

Sniffer::Sniffer()
{
	pb=NULL;
	pcap_initted=false;
	pthread_initted=false;
	pthread_mutex_init( &pb_mutex, NULL );
}

void Sniffer::dest( PacketBuffer *npb )
{
	assert( pthread_mutex_lock(&pb_mutex)==0 );
	pb=npb;
	assert( pthread_mutex_unlock(&pb_mutex)==0 );
}

void Sniffer::init(char *iface, char *fexp, char *test_file)
{
	assert(pcap_initted==false);
	assert(pthread_initted==false);

	char errbuf[PCAP_ERRBUF_SIZE]; // error messages stored here

	//
	// open the network interface for sniffing
	//
	if( test_file == NULL )
	{
		if( app->promisc )
			handle = pcap_open_live(iface, SNAPLEN, 1, POL_TO_MS, errbuf);
		else
			handle = pcap_open_live(iface, SNAPLEN, 0, POL_TO_MS, errbuf);
	}
	else
	{
		handle = pcap_open_offline(test_file, errbuf);
	}
		
	if( !handle )
		throw PcapError("pcap_open_live",errbuf);
	
	dlt = pcap_datalink(handle);
	if( dlt!=DLT_EN10MB  &&  dlt!=DLT_LINUX_SLL && dlt!=DLT_RAW && dlt!=DLT_NULL) 
		throw GenericError("The specified interface type is not supported yet.");
	//if( dlt==DLT_LINUX_SLL )
	//	cerr << "this is a LINUX_SLL interface\n";

	//
	// prepare the filter	
	//
	struct bpf_program filter; // the filter for the sniffer
	char *filter_app = fexp;  // The filter expression
	bpf_u_int32 mask;  // The netmask of our sniffing device
	bpf_u_int32 net;    // The IP of our sniffing device
	if( pcap_lookupnet(iface, &net, &mask, errbuf) == -1 )
	{
		// TODO: should this ever be fatal? 
		//       it never is in tcpdump.
		//pcap_close(handle);
		//throw PcapError("pcap_lookupnet",errbuf);
		net = 0;
		mask = 0;
	}
	if( pcap_compile(handle, &filter, filter_app, 0, net) == -1 )
	{
		pcap_close(handle);
		throw PcapError("pcap_compile",pcap_geterr(handle));
	}
	if( pcap_setfilter(handle, &filter) ) // apply filter to sniffer
	{
		pcap_freecode(&filter);
		pcap_close(handle);
		throw PcapError("pcap_setfilter",pcap_geterr(handle));
	}
	pcap_freecode(&filter); // filter code not needed after setfilter
	
	pcap_initted=true;


	pthread_attr_t attr;

	if( pthread_attr_init( &attr ) != 0 )
		throw GenericError("pthread_attr_init() failed");

	pthread_attr_setstacksize( &attr, SS_S );

	if( pthread_create(&sniffer_tid,&attr,sniffer_thread_func,this) != 0 )
		throw GenericError("pthread_create() failed.");

	pthread_initted=true;
}

Sniffer::~Sniffer()
{
	if( pthread_initted ) 
	{
		// if pthread_cancel returns non-zero, this indicates that
		// sniffer_tid is not valid. It may have stopped because of
		// an exception. Don't bother joining in that case.

		if( pthread_cancel(sniffer_tid) == 0 )
			pthread_join(sniffer_tid,NULL);
	}
	if( pcap_initted )
		pcap_close(handle);
}

// this method gets run in a new thread.
// it should only be called from sniffer_thread_func, never from anywhere
// else.
void Sniffer::run()
{
	u_char *other = (u_char *) this;

	if( pcap_loop(handle, -1, handle_packet, other) == -1 )
		throw PcapError("pcap_loop",pcap_geterr(handle));

	// Kill the program when the loop ends.
	// We return 0 so the fuzz tester can tell the difference between a good run and a crash
	exit(0);
}

void Sniffer::processPacket( const pcap_pkthdr *header, const u_char *packet )
{
	assert( pthread_mutex_lock(&pb_mutex)==0 );

	if( pb==NULL ) 
	{
		assert( pthread_mutex_unlock(&pb_mutex) == 0 );
		return;
	}

	// getnlp parses the link level header. n.p will point to the network
	// layer header.
	struct nlp *n = getnlp(packet,dlt,header);
	if( ! n )
	{
		assert( pthread_mutex_unlock(&pb_mutex) == 0 );
		return;
	}
	
	if( ! checknlp(n) )
	{
		if( n->p != NULL )
			free(n->p);
		free(n);
		assert( pthread_mutex_unlock(&pb_mutex) == 0 );
		return;
	}

	// TODO: if this throws exceptions, unlock pb_mutex before rethrow.
	// So far, PacketBuffer doesn't throw any exceptions here.
	pb->pushPacket(n);
	
	assert( pthread_mutex_unlock(&pb_mutex) == 0 );
}

//////////////////////


// callback for pthread_create, gets executed in a newly created thread.
void *sniffer_thread_func(void *arg)
{
	Sniffer *sniffer = (Sniffer *) arg;
	try 
	{
		sniffer->run();
	} 
	catch( const AppError &e )
	{
		app->fatal(e.msg());
	}
	return NULL;
}

// callback function called by pcap_loop every time it receives a packet
void handle_packet(u_char *other, const struct pcap_pkthdr *header, const u_char *packet)
{
	Sniffer *sniffer = (Sniffer *) other;
	sniffer->processPacket(header,packet);
}

