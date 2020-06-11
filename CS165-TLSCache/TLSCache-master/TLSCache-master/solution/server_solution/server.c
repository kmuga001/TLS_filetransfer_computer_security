#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

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
	fprintf(stderr, "usage: %s portnumber\n", __progname);
	exit(1);
}

static void kidhandler(int signum) {
	/* signal handler for SIGCHLD */
	waitpid(WAIT_ANY, NULL, WNOHANG);
}


int main(int argc,  char *argv[])
{
	struct sockaddr_in sockname, client;
	//char buffer[80], *ep;
	char buffer[1000], *ep;
	struct sigaction sa;
	int sd, i;
	socklen_t clientlen;
	u_short port;
	pid_t pid;
	u_long p;
	struct tls_config *tls_cfg = NULL; // TLS config
	struct tls *tls_ctx = NULL; // TLS context
	struct tls *tls_cctx = NULL; // client's TLS context

	/*
	 * first, figure out what port we will listen on - it should
	 * be our first parameter.
	 */

	if (argc != 2)
		usage();
		errno = 0;
        p = strtoul(argv[1], &ep, 10);
        if (*argv[1] == '\0' || *ep != '\0') {
		/* parameter wasn't a number, or was empty */
		fprintf(stderr, "%s - not a number\n", argv[1]);
		usage();
	}
        if ((errno == ERANGE && p == ULONG_MAX) || (p > USHRT_MAX)) {
		/* It's a number, but it either can't fit in an unsigned
		 * long, or is too big for an unsigned short
		 */
		fprintf(stderr, "%s - value out of range\n", argv[1]);
		usage();
	}
	/* now safe to do this */
	port = p;



	/* set up TLS */

	/* set up TLS */
        char cwd[100000];
        const char* tempfile = getcwd(cwd, sizeof(cwd));

        /*ROOT_PEM*/
        char des_r[100000];
        strcat(des_r, tempfile);
        strcat(des_r, "/certificates/root.pem");

        /*SERVER_CRT*/
        char des_scrt[100000];
        strcat(des_scrt, tempfile);
        strcat(des_scrt, "/certificates/server.crt");

        /*SERVER.KEY*/
        char des_skey[100000];
        strcat(des_skey, tempfile);
        strcat(des_skey, "/certificates/server.key");




	if ((tls_cfg = tls_config_new()) == NULL)
		errx(1, "unable to allocate TLS config");
	if (tls_config_set_ca_file(tls_cfg, des_r) == -1)
		errx(1, "unable to set root CA file");
	if (tls_config_set_cert_file(tls_cfg, des_scrt) == -1) 
		errx(1, "unable to set TLS certificate file, error: (%s)", tls_config_error(tls_cfg));
	if (tls_config_set_key_file(tls_cfg, des_skey) == -1)
		errx(1, "unable to set TLS key file");
	if ((tls_ctx = tls_server()) == NULL)
		errx(1, "TLS server creation failed");
	if (tls_configure(tls_ctx, tls_cfg) == -1)
		errx(1, "TLS configuration failed (%s)", tls_error(tls_ctx));

	/* the message we send the client */
	/*strlcpy(buffer,
	    "It was the best of times, it was the worst of times... \n",
	    sizeof(buffer));
	*/


	/*get filename's path!!!! */
	char cwd_file[10000];
	const char* temp_f = getcwd(cwd_file, sizeof(cwd_file));
	char filepath[10000];
	strcat(filepath, temp_f);
	strcat(filepath, "/solution/testing_files/test1.txt"); /*the last part is where client's filename goes */
	

	/*get file contents and put it into the buffer */
	FILE *file;
	char c;
	file = fopen(filepath, "r");
	if(file == NULL) {
		err(1, "ERROR: file failed to open");
	}
	//c = fgetc(file);
	while(c != EOF) {
		c = fgetc(file);
		if(c == '\n') {
			break;
		}
		strncat(buffer, &c, 1);
		
	}
	fclose(file);


	memset(&sockname, 0, sizeof(sockname));
	sockname.sin_family = AF_INET;
	sockname.sin_port = htons(port);
	sockname.sin_addr.s_addr = htonl(INADDR_ANY);
	sd=socket(AF_INET,SOCK_STREAM,0);
	if ( sd == -1)
		err(1, "socket failed");

	if (bind(sd, (struct sockaddr *) &sockname, sizeof(sockname)) == -1)
		err(1, "bind failed");

	if (listen(sd,3) == -1)
		err(1, "listen failed");

	/*
	 * we're now bound, and listening for connections on "sd" -
	 * each call to "accept" will return us a descriptor talking to
	 * a connected client
	 */


	/*
	 * first, let's make sure we can have children without leaving
	 * zombies around when they die - we can do this by catching
	 * SIGCHLD.
	 */
	sa.sa_handler = kidhandler;
        sigemptyset(&sa.sa_mask);
	/*
	 * we want to allow system calls like accept to be restarted if they
	 * get interrupted by a SIGCHLD
	 */
        sa.sa_flags = SA_RESTART;
        if (sigaction(SIGCHLD, &sa, NULL) == -1)
                err(1, "sigaction failed");

	/*
	 * finally - the main loop.  accept connections and deal with 'em
	 */
	printf("Server up and listening for connections on port %u\n", port);
	for(;;) {
		int clientsd;
		clientlen = sizeof(&client);
		clientsd = accept(sd, (struct sockaddr *)&client, &clientlen);
		if (clientsd == -1)
			err(1, "accept failed");
		/*
		 * We fork child to deal with each connection, this way more
		 * than one client can connect to us and get served at any one
		 * time.
		 */

		pid = fork();
		if (pid == -1)
		     err(1, "fork failed");

		if(pid == 0) {
			ssize_t written, w;
			i = 0;
			if (tls_accept_socket(tls_ctx, &tls_cctx, clientsd) == -1)
				errx(1, "tls accept failed (%s)", tls_error(tls_ctx));
			else {
				do {
					if ((i = tls_handshake(tls_cctx)) == -1)
						errx(1, "tls handshake failed (%s)", tls_error(tls_ctx));
				} while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);
			}

			/*
			 * write the message to the client, being sure to
			 * handle a short write, or being interrupted by
			 * a signal before we could write anything.
			 */
			w = 0;
			written = 0;
			while (written < strlen(buffer)) {
				w = tls_write(tls_cctx, buffer + written,
				    strlen(buffer) - written);

				if (w == TLS_WANT_POLLIN || w == TLS_WANT_POLLOUT)
					continue;

				if (w < 0) {
					errx(1, "TLS write failed (%s)", tls_error(tls_cctx));
				}
				else
					written += w;
				printf("IM WHILE WRITING %s\n", "SERVER_SOLUTION");
			}
			i = 0;
			do {
				i = tls_close(tls_cctx);
			} while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);

			close(clientsd);
			exit(0);
		}
		close(clientsd);
	}
}
