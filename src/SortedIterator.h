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
#ifndef SORTEDITERATOR_H
#define SORTEDITERATOR_H

#define SORT_UN 1
#define SORT_RATE 2
#define SORT_BYTES 3

class TCContainer;
class TCPConnection;

int compare_rate(const void *, const void *);
int compare_bytes(const void *, const void *);

class SortedIterator
{
public:
	SortedIterator( TCContainer *c );
	~SortedIterator();
	TCPConnection * getNext();
	void sort( int sort_type );
	void rewind();
private:
	TCPConnection **cons;
	unsigned int numcons;
	unsigned int cur;
};

#endif
