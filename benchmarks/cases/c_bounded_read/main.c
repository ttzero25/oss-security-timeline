#include <unistd.h>

void receive_packet(int socket_fd) {
    char packet[16];
    read(socket_fd, packet, sizeof(packet));
}
