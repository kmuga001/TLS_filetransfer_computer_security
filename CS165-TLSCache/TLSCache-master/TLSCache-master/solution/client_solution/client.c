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

int main(int argc, char *argv[])
{
	struct sockaddr_in server_sa;
	char buffer[80], *ep;
	size_t maxread;
	ssize_t r, rc;
	u_short port;
	u_long p;
	int sd, i;
	struct tls_config *tls_cfg = NULL;
	struct tls *tls_ctx = NULL;

	if (argc != 4)
		usage();

        p = strtoul(argv[2], &ep, 10);
        if (*argv[2] == '\0' || *ep != '\0') {
		/* parameter wasn't a number, or was empty */
		fprintf(stderr, "%s - not a number\n", argv[2]);
		usage();
	}
        if ((errno == ERANGE && p == ULONG_MAX) || (p > USHRT_MAX)) {
		/* It's a number, but it either can't fit in an unsigned
		 * long, or is too big for an unsigned short
		 */
		fprintf(stderr, "%s - value out of range\n", argv[2]);
		usage();
	}
	/* now safe to do this */
	port = p;

	/* set up TLS */
	char cwd[100000];
        const char* tempfile = getcwd(cwd, sizeof(cwd));

        /*ROOT_PEM*/
        char des_r[100000];
        strcat(des_r, tempfile);
        strcat(des_r, "/certificates/root.pem");


	if (tls_init() == -1)
		errx(1, "unable to initialize TLS");
	if ((tls_cfg = tls_config_new()) == NULL)
		errx(1, "unable to allocate TLS config");
	if (tls_config_set_ca_file(tls_cfg, des_r) == -1)
		errx(1, "unable to set root CA file");
	


	/*
	 * first set up "server_sa" to be the location of the server
	 */
	memset(&server_sa, 0, sizeof(server_sa));
	server_sa.sin_family = AF_INET;
	server_sa.sin_port = htons(port);
	server_sa.sin_addr.s_addr = inet_addr(argv[1]);
	if (server_sa.sin_addr.s_addr == INADDR_NONE) {
		fprintf(stderr, "Invalid IP address %s\n", argv[1]);
		usage();
	}
	
	/* ok now get a socket. */
	if ((sd=socket(AF_INET,SOCK_STREAM,0)) == -1)
		err(1, "socket failed");

	/* connect the socket to the server described in "server_sa" */
	if (connect(sd, (struct sockaddr *)&server_sa, sizeof(server_sa)) == -1)
		err(1, "connect failed");

	if ((tls_ctx = tls_client()) == NULL)
		errx(1, "tls client creation failed");
	if (tls_configure(tls_ctx, tls_cfg) == -1)
		errx(1, "tls configuration failed (%s)", tls_error(tls_ctx));
	if (tls_connect_socket(tls_ctx, sd, "localhost") == -1)
		errx(1, "tls connection failed (%s)", tls_error(tls_ctx));
	

	do {
		if ((i = tls_handshake(tls_ctx)) == -1)
			errx(1, "tls handshake failed (%s)", tls_error(tls_ctx));
	} while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);

	/*
	 * finally, we are connected. find out what magnificent wisdom
	 * our server is going to send to us - since we really don't know
	 * how much data the server could send to us, we have decided
	 * we'll stop reading when either our buffer is full, or when
	 * we get an end of file condition from the read when we read
	 * 0 bytes - which means that we pretty much assume the server
	 * is going to send us an entire message, then close the connection
	 * to us, so that we see an end-of-file condition on the read.
	 *
	 * we also make sure we handle EINTR in case we got interrupted
	 * by a signal.
	 */


	/*TRYING TO SEND FILENAME TO PROXY USING TLS_WRITE */

	char buff_file[200];
	ssize_t w;

	strcat(buff_file, argv[3]);
	/*printf("this is buff_file: %s\n", buff_file);*/
	ssize_t templen = strnlen(buff_file, sizeof(buff_file));
	if((w = tls_write(tls_ctx, buff_file, templen)) != templen) {
		errx(1, "Failed to write message");
	} 


	/*w = 0;
	written = 0;
	while(written < strlen(buff_file)) {
		w = tls_write(tls_ctx, buff_file + written, strlen(buff_file) - written);

		if(w == TLS_WANT_POLLIN || w == TLS_WANT_POLLOUT)
			continue;
		if(w < 0){
			errx(1, "TLS client's write failed");
		} else {
			written += w;
		}
	}
	*/


	r = -1;
	rc = 0;
	maxread = sizeof(buffer) - 1; /* leave room for a 0 byte */
	while ((r != 0) && rc < maxread) {
		/*printf("IN THE WHILEEEE READ %s\n", "CLIENT");*/
		r = tls_read(tls_ctx, buffer + rc, maxread - rc);
		if (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT)
			continue;
		if (r < 0) {
			err(1, "tls_read failed (%s)", tls_error(tls_ctx));
		} else
			rc += r;
	}
	/*
	 * we must make absolutely sure buffer has a terminating 0 byte
	 * if we are to use it as a C string
	 */
	buffer[rc] = '\0';

	printf("Server sent:  %s",buffer);
	close(sd);
	return(0);
}
