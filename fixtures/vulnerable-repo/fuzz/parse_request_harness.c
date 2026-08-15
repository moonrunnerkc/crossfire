#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "parse_request.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *line = malloc(size + 1);
  if (line == NULL) {
    return 0;
  }
  memcpy(line, data, size);
  line[size] = '\0';

  /* Heap allocated so the sanitizer reports the overflow against a real
     allocation with a readable redzone. */
  struct request *req = malloc(sizeof(struct request));
  if (req != NULL) {
    parse_request(line, req);
    free(req);
  }

  free(line);
  return 0;
}
