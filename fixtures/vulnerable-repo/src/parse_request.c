#include "parse_request.h"

#include <string.h>

/* Build with -DPARSE_REQUEST_FIXED to compile the patched parser. The fixture
   ships both so the detection gates can show a crash and its absence from the
   same source. */

int parse_request(const char *line, struct request *out) {
  const char *space = strchr(line, ' ');
  if (space == NULL) {
    return -1;
  }

  size_t method_len = (size_t)(space - line);
#ifdef PARSE_REQUEST_FIXED
  if (method_len >= sizeof(out->method)) {
    return -1;
  }
#endif
  memcpy(out->method, line, method_len);
  out->method[method_len] = '\0';

  const char *path = space + 1;
#ifdef PARSE_REQUEST_FIXED
  size_t path_len = strlen(path);
  if (path_len >= sizeof(out->path)) {
    return -1;
  }
  memcpy(out->path, path, path_len + 1);
#else
  strcpy(out->path, path);
#endif

  return 0;
}
