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
#ifndef TEXTUI_H
#define TEXTUI_H 1

#define _DEFAULT_SOURCE 1
#define _REENTRANT
#include <curses.h>
#include <pthread.h>
#include "TCContainer.h"
#include "SortedIterator.h"

#define USTATE_IDLE 1
#define USTATE_RUNNING 2
#define USTATE_STOPPING 3
#define USTATE_DONE 4

class TextUI
{
public:
	TextUI( TCContainer * );
	~TextUI();

	void init(); // like a constructor, but exceptions can be thrown.
	void stop();

	// try to make the terminal modes sane again during an unclean 
	// exit.
	static void reset();

	// do not call. used as pthread_create callback.
	void displayer_run();
private:
	void drawui(); // draw the screen.
	void print_bps(int); // display the speed with the right format

	bool run_displayer;

	// display packets in here.
	TCContainer *container;

	// an iterator over connections in the container.
	SortedIterator * iter;

	// number of the last line on the screen.
	int bottom;
	// size of the terminal
	int size_x;
	int size_y;

	// how far into the container we start the listing... for scrolling.
	unsigned int doffset; 

	int state;
	pthread_mutex_t state_mutex;

	bool paused;

	int sort_type;

	// TODO: moving this pthread_t var up to the top of the private block
	// and adding an int in the middle will cause initscr() to segfault
	// (deep in initscr)... should figure out why someday.
	pthread_t displayer_tid; 
};

void *displayer_thread_func( void * );

#endif
