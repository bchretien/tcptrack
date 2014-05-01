#ifndef GENERICERROR_H
#define GENERICERROR_H 1

#include <string>
#include "AppError.h"

using namespace std;

// this is a general exception used for lots of things
// ...mainly because I haven't gotten around to making more useful
// exception classes yet.

class GenericError : public AppError
{
public:
	GenericError( const char *msg );
	GenericError( string msg ) { m=msg; };
	GenericError( const GenericError &ge );
  virtual ~GenericError() { }

	string msg() const;
private:
	string m;
};

#endif
