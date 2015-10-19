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

  if (addr->sa_family == AF_INET) {
    len = sizeof(struct sockaddr_in);
  } else if (addr->sa_family == AF_INET6) {
    len = sizeof(struct sockaddr_in6);
  }

  if (!addr) {
    return -1;
  }

  if (addr->sa_family == AF_INET) {
    sfamily = PF_INET;
  } else if (addr->sa_family == AF_INET6) {
    sfamily = PF_INET6;
  }

  sockfd = socket(sfamily, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("Failed to create socket.");
    return -1;
  }
  rc = bind(sockfd, addr, len);
  if (rc < 0) {
    perror("Failed to bind to address.");
    return -1;
  }
  return sockfd;
}

int do_listen(int sockfd, int backlogc) {
  if (sockfd < 0) {
    return -1;
  }
  return listen(sockfd, backlogc);
}

int do_server(const char *ip, int port) {
  int rc, sockfd, len = 0;
  socklen_t addr_size;
  struct sockaddr *addr;

  rc = resolve_name_to_addr(ip, port, &addr);
  if (rc) {
    perror("resolve");
  }

  if (addr->sa_family == AF_INET) {
    len = sizeof(struct sockaddr_in);
  } else if (addr->sa_family == AF_INET6) {
    len = sizeof(struct sockaddr_in6);
  }

  sockfd = do_bind(addr);
  if (sockfd< 0) {
    perror("bind");
    return -1;
  }
  fprintf(stdout,"Bind : success %s:%d\n",ip,port);

  rc = do_listen(sockfd, 10);
  if (rc != 0) {
    perror("listen");
    return -1;
  }
  fprintf(stdout,"Listen : success %s:%d\n",ip,port);

  rc = accept(sockfd, addr, &addr_size);
  if (rc < 0) {
    perror("accept");
    return -1;
  }

  return sockfd;
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
