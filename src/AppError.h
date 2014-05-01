#ifndef APPERROR_H
#define APPERROR_H 1

#include <string>

using namespace std;

// AppError is an abstract base class for all exceptions in TCPTrack

class AppError
{
public:
  AppError() { }
  virtual ~AppError() { }

	virtual string msg() const = 0;
};

#endif
