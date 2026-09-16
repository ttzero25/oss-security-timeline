#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void command_from_network(int socket_fd) {
    char command[256];
    read(socket_fd, command, sizeof(command));
    system(command);
}

void format_from_environment(void) {
    char *message = getenv("MESSAGE");
    printf(message);
}

void safe_output(int socket_fd) {
    char text[256];
    read(socket_fd, text, sizeof(text));
    printf("%s", text);
}

void guarded_copy(char *argv[]) {
    char destination[16];
    const char *value = argv[1];
    if (strlen(value) >= sizeof(destination)) {
        return;
    }
    strcpy(destination, value);
}
