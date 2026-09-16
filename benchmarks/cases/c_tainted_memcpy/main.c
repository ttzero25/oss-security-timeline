#include <stdlib.h>
#include <string.h>

void copy_environment(void) {
    char destination[16];
    const char *payload = getenv("PAYLOAD");
    size_t length = strtoul(getenv("LENGTH"), NULL, 10);
    memcpy(destination, payload, length);
}
