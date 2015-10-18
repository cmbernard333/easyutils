#include "net_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int resolve_name_to_addr(const char *name, int port, struct sockaddr **out) {
  int rc = 0;
  int family = AF_INET;
  struct addrinfo hints, *res;
  struct sockaddr *ret;
  char sPort[15];

  sprintf(sPort, "%d", port);

  if (strchr(name, ':')) {
    family = AF_INET6;
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = family;
  hints.ai_socktype = SOCK_STREAM;

  if ((rc = getaddrinfo(name, sPort, &hints, &res))) {
    perror("Failed to resolve name.");
    return 2;
  }

  while (res) {
    sockaddr_printf(stdout, res->ai_addr);
    /* resolve the first ip address */
    if (res->ai_family == AF_INET) {
      struct sockaddr_in *in = (struct sockaddr_in *)res->ai_addr;
      ret = (struct sockaddr *)in;
    } else if (res->ai_family == AF_INET6) {
      struct sockaddr_in6 *in = (struct sockaddr_in6 *)res->ai_addr;
      ret = (struct sockaddr *)in;
    }
    res = res->ai_next;
  }

  *out = ret;

  return 0;
}

int do_bind(struct sockaddr *addr) {
  int sockfd, sfamily, rc, len;

  if (!addr) {
    return 1;
  }

  if (addr->sa_family == AF_INET) {
    sfamily = PF_INET;
  } else if (addr->sa_family == AF_INET6) {
    sfamily = PF_INET6;
  }

  sockfd = socket(sfamily, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("Failed to create socket.");
    return 1;
  }
  rc = bind(sockfd, addr, sizeof(addr));
  if (rc < 0) {
    perror("Failed to bind to address.");
    return 1;
  }
  close(sockfd);
  return 0;
}

int sockaddr_printf(FILE *file, struct sockaddr *addr) {
  int rc, len, port = 0;
  char *ip;
  char ipv[5];
  void *vaddr;
  if (addr->sa_family == AF_INET) {
    struct sockaddr_in *in = (struct sockaddr_in *)addr;
    ip = (char *)calloc(1, INET_ADDRSTRLEN);
    len = INET_ADDRSTRLEN;
    vaddr = &(in->sin_addr);
    port = ntohs(in->sin_port);
    sprintf(ipv, "%s", "ipv4");
  } else if (addr->sa_family == AF_INET6) {
    struct sockaddr_in6 *in = (struct sockaddr_in6 *)addr;
    ip = (char *)calloc(1, INET6_ADDRSTRLEN);
    len = INET6_ADDRSTRLEN;
    vaddr = &(in->sin6_addr);
    port = ntohs(in->sin6_port);
    sprintf(ipv, "%s", "ipv6");
  }
  inet_ntop(addr->sa_family, vaddr, ip, len);
  rc = fprintf(file, "%s->%s:%d\n", ipv, ip, port);
  free(ip);
  return rc;
}
