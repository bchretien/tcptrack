#ifndef PCAPERROR_H
#define PCAPERROR_H

#include "AppError.h"
#include <string>

using namespace std;

// this exception is thrown when a pcap_*() function call returns an error.

class PcapError : public AppError
{
public:
	PcapError( const char *func, char *errbuf );
	PcapError( const PcapError &e );
	string msg() const;
private:
	string f;
	string e;
};

#endif
