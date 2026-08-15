#ifndef PARSE_REQUEST_H
#define PARSE_REQUEST_H

#include <stddef.h>

struct request {
  char method[8];
  char path[32];
};

/* Parses "<METHOD> <PATH>" out of a NUL terminated request line into out.
   Returns 0 when the line parsed, -1 when it is not a request line. */
int parse_request(const char *line, struct request *out);

#endif
