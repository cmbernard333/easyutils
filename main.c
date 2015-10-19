#include <stdio.h>
#include <unistd.h>
#include "net_utils.h"
#include "easy_ssl.h"

int main(int argc, char** argv)
{
    const char* name = argv[1];
    int rc = 0;

    rc = do_server(name,48000);
    if(rc)
    {
    	fprintf(stderr,"Failed to bind to %s:%d. RC=%d\n",name,48000,rc);
    }
    close(rc);
    return 0;
}
