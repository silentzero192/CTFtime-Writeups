#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

typedef int (*bind_fn_t)(int, const struct sockaddr *, socklen_t);

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    static bind_fn_t real_bind = NULL;
    struct sockaddr_in patched;

    if (real_bind == NULL) {
        real_bind = (bind_fn_t)dlsym(RTLD_NEXT, "bind");
    }

    if (addr != NULL && addr->sa_family == AF_INET && addrlen >= sizeof(patched)) {
        memcpy(&patched, addr, sizeof(patched));
        if (ntohs(patched.sin_port) == 8080) {
            patched.sin_port = htons(18080);
            return real_bind(sockfd, (const struct sockaddr *)&patched, sizeof(patched));
        }
    }

    return real_bind(sockfd, addr, addrlen);
}
