#include <stdlib.h>

int main(int argc, char **argv) {
    char *command = argv[1];
    return system(command);
}
