#ifndef TCPHEADER_H
#define TCPHEADER_H 1
#define __FAVOR_BSD 1

#include <netinet/in.h>

typedef unsigned short portnum_t;
typedef unsigned int   seq_t;

const uint8_t FIN = 0x01;
const uint8_t SYN = 0x02;
const uint8_t RST = 0x04;
const uint8_t PSH = 0x08;
const uint8_t ACK = 0x10;
const uint8_t URG = 0x20;
const uint8_t ECE = 0x40;
const uint8_t CWR = 0x80;

class TCPHeader
{
public:
	TCPHeader( const u_char *data, unsigned int data_len );
	TCPHeader( TCPHeader & orig );
	seq_t getSeq() const;
	seq_t getAck() const;
	bool isFlagSet(unsigned int);
	unsigned short headerLen() const { return header_len; };

	portnum_t srcPort() const;
	portnum_t dstPort() const;

	bool fin() const;
	bool syn() const;
	bool rst() const;
	bool psh() const;
	bool ack() const;
	bool urg() const;
	bool ece() const;
	bool cwr() const;

private:
	seq_t seqn;
	seq_t ackn;
	portnum_t src;
	portnum_t dst;
	unsigned char flags;
	unsigned short header_len;
};

#endif
