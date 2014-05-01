#include <cassert>
#include <string>
#include "GenericError.h"

using namespace std;

GenericError::GenericError( const char *msg )
{
	m=msg;
}

GenericError::GenericError( const GenericError &ge )
{
	m=ge.m;
}

string GenericError::msg() const
{
	return m;
}
