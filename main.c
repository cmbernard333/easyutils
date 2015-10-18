#include <stdio.h>
#include "net_utils.h"

int main(int argc, char** argv)
{
    const char* name = argv[1]; 
    struct sockaddr* addr;
    int rc = 0;
    rc = resolve_name_to_addr(name, 48000, &addr);
    if(rc)
    {
    	fprintf(stderr,"Failed to resolve %s. RC=%d\n",name,rc);
    }

    sockaddr_printf(stdout,addr);

    rc = do_bind(addr);
    if(rc)
    {
    	fprintf(stderr,"Failed to bind to %s:%d. RC=%d\n",name,48000,rc);
    }
    return 0;
}
