#include <arpa/inet.h>

#include <netinet/in.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <tls.h>

static void usage()
{       
        extern char * __progname;
        fprintf(stderr, "usage: %s ipaddress portnumber\n", __progname);
        exit(1);
}

