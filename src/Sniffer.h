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
#ifndef SNIFFER_H
#define SNIFFER_H 1

#define _DEFAULT_SOURCE 1
#define _BSD_SOURCE 1
#define _REENTRANT

#ifdef HAVE_PCAP_PCAP_H
#include <pcap/pcap.h>
#endif
#ifdef HAVE_PCAP_H
#include <pcap.h>
#endif
#include <pthread.h>
#include "PacketBuffer.h"

class Sniffer
{
public:
	Sniffer();
	~Sniffer();

	// init performs some constructor-like activity. It is separate
	// so that exceptions don't have to be thrown in the constructor.
	void init(char *iface, char *fexp, char *test_file);

	// set the place where sniffed packets are sent for further 
	// processing. If NULL, packets are just dropped.
	void dest( PacketBuffer *pb=NULL );

	
	// do not call. called only from the pcap_loop loopback function. 
	void processPacket(const pcap_pkthdr *header, const u_char *packet);

	// do not call. called only from sniffer_thread_func
	void run(); 
	
private:
	pthread_t sniffer_tid; // thread id of sniffer thread
	pcap_t *handle;        // device handle, for net dev we're sniffing
	PacketBuffer *pb;      // send packets here. may be NULL.
	pthread_mutex_t pb_mutex;

	// these are true if these parts were successfully initialzised, 
	// and thus would need to be cleaned up in the constructor.
	// also used to make sure init() isn't called more than once.
	bool pcap_initted;
	bool pthread_initted;

	// the data link type. set to one of the DLT_* values in 
	// net/bpf.h. Specifies what type of link layer this is 
	// (ethernet, ppp, raw IP...)
	int dlt;
};

// pcap_loop calls this function
void handle_packet(u_char *other, const struct pcap_pkthdr *header, const u_char *packet);

// main function for sniffer thread
void *sniffer_thread_func(void *);

#endif
