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
#define _REENTRANT
#include "../config.h" // for PACKAGE and VERSION
#include <stdio.h>
#include <unistd.h> // for getopt & pause
#include <limits.h> // for ARG_MAX
#include <signal.h> // for setting up sig handlers w/sigaction
#include "TCContainer.h"
#include "TextUI.h"
#include "util.h"
#include "PacketBuffer.h"
#include "Sniffer.h"
#include "TCPTrack.h"

// the global application object.
extern TCPTrack *app;

// cleanly quit tcptrack on sigint
void inthandler(int sig)
{
	signal(SIGINT,SIG_IGN);
	if( app != NULL )
		app->shutdown();
	else
		exit(0);
	return;
}

int main(int argc, char **argv)
{
	extern TCPTrack *app;
	
	// make a SIGINT do a clean shutdown
	signal(SIGINT,inthandler);

	app=new TCPTrack();
	app->run(argc,argv);
}

