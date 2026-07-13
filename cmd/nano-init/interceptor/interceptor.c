#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

// Function pointer to the original connect syscall
static int (*original_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;

static void init(void) __attribute__((constructor));
static void init(void) {
    original_connect = dlsym(RTLD_NEXT, "connect");
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!original_connect) {
        fprintf(stderr, "[interceptor] Error: original connect not initialized\n");
        errno = EFAULT;
        return -1;
    }

    struct sockaddr_storage modified_addr;
    const struct sockaddr *final_addr = addr;

    if (addr && (addr->sa_family == AF_INET || addr->sa_family == AF_INET6)) {
        char *proxy_port_str = getenv("SAM_PROXY_PORT");
        if (proxy_port_str) {
            int proxy_port = atoi(proxy_port_str);
            if (proxy_port > 0 && proxy_port < 65536) {
                if (addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
                    struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
                    uint16_t port = ntohs(addr4->sin_port);
                    if (port == 80 || port == 443) {
                        memcpy(&modified_addr, addr, sizeof(struct sockaddr_in));
                        struct sockaddr_in *m_addr4 = (struct sockaddr_in *)&modified_addr;
                        m_addr4->sin_port = htons(proxy_port);
                        m_addr4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                        final_addr = (const struct sockaddr *)&modified_addr;
                    }
                } else if (addr->sa_family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {
                    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
                    uint16_t port = ntohs(addr6->sin6_port);
                    if (port == 80 || port == 443) {
                        memcpy(&modified_addr, addr, sizeof(struct sockaddr_in6));
                        struct sockaddr_in6 *m_addr6 = (struct sockaddr_in6 *)&modified_addr;
                        m_addr6->sin6_port = htons(proxy_port);
                        m_addr6->sin6_addr = in6addr_loopback;
                        final_addr = (const struct sockaddr *)&modified_addr;
                    }
                }
            }
        }
    }

    return original_connect(sockfd, final_addr, addrlen);
}
