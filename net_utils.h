#ifndef __NET_UTILS_H__
#define __NET_UTILS_H__
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
/* resolves name and port to a sockaddr object */
extern int resolve_name_to_addr(const char* name, int port, struct sockaddr **out);
/* does a bind to the given sockaddr object */
extern int do_bind(struct sockaddr *addr);
/* prints the ip address of this sockaddr to a fd */
extern int sockaddr_printf(FILE* f, struct sockaddr *addr);
#endif
