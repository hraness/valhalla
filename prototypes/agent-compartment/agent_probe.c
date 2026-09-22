/* Controlled synthetic agent: no secrets, interpreter, shell or provider SDK. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_FRAME 4096

static int denied(void) { return errno == EPERM || errno == EACCES; }
static int exact(int fd, void *buffer, size_t count, int writing) {
    unsigned char *at = buffer;
    while (count) {
        ssize_t n = writing ? write(fd, at, count) : read(fd, at, count);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        at += n;
        count -= (size_t)n;
    }
    return 0;
}
static int denied_open(const char *path, int flags) {
    int fd = open(path, flags);
    if (fd >= 0) { close(fd); return 0; }
    return denied();
}
static int denied_tcp(unsigned short port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return denied();
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    int result = connect(fd, (struct sockaddr *)&address, sizeof(address));
    int refused = result < 0 && denied();
    close(fd);
    return refused;
}
static int denied_unix(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return denied();
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(address.sun_path)) { close(fd); return 0; }
    memcpy(address.sun_path, path, strlen(path) + 1);
    int result = connect(fd, (struct sockaddr *)&address, sizeof(address));
    int refused = result < 0 && denied();
    close(fd);
    return refused;
}
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    uint32_t length;
    unsigned char message[MAX_FRAME];
    if (exact(STDIN_FILENO, &length, 4, 0)) return 3;
    length = ntohl(length);
    if (!length || length >= MAX_FRAME) return 4;
    if (exact(STDIN_FILENO, message + 1, length, 0)) return 5;
    unsigned char checks = 0;
    if (denied_open(argv[1], O_RDONLY)) checks |= 1;
    if (denied_open(argv[1], O_WRONLY)) checks |= 2;
    if (denied_tcp((unsigned short)strtoul(argv[2], NULL, 10))) checks |= 4;
    pid_t child = fork();
    if (child == 0) _exit(90);
    if (child < 0 && denied()) checks |= 8;
    if (child > 0) (void)waitpid(child, NULL, 0);
    if (denied_unix(argv[3])) checks |= 16;
    char *const args[] = {"/usr/bin/true", NULL};
    char *const clean_env[] = {NULL};
    /* An allowed exec produces no response, so the trusted parent fails closed. */
    execve(args[0], args, clean_env);
    if (denied()) checks |= 32;
    message[0] = checks;
    length++;
    uint32_t wire_length = htonl(length);
    if (exact(STDOUT_FILENO, &wire_length, 4, 1)) return 6;
    if (exact(STDOUT_FILENO, message, length, 1)) return 7;
    return checks == 63 ? 0 : 8;
}
