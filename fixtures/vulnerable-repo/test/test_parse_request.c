/* The target's own test suite. It exercises well formed request lines only, so
   it passes against both the vulnerable and the patched parser. That is the
   point: it is the regression baseline a fix must not break, not a bug finder. */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "parse_request.h"

int main(void) {
  struct request req;

  assert(parse_request("GET /", &req) == 0);
  assert(strcmp(req.method, "GET") == 0);
  assert(strcmp(req.path, "/") == 0);

  assert(parse_request("POST /submit", &req) == 0);
  assert(strcmp(req.method, "POST") == 0);
  assert(strcmp(req.path, "/submit") == 0);

  assert(parse_request("no-space-here", &req) == -1);

  printf("parse_request: 3 tests passed\n");
  return 0;
}
