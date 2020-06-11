#include <arpa/inet.h> /*COMING FROM CLIENT*/

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

//using namespace std;

static void usage()
{
	extern char * __progname;
	fprintf(stderr, "usage: %s portnumber\n", __progname);
	exit(1);
}

/*OVERVIEW:
 * treating proxy as a SERVER base, however when we need the server's
 * message, proxy will act as a client and read the message the server gave in buffer.
 * After reading the message, the proxy will write that into the buffer so that client can read it*/

static void kidhandler(int signum) {
	/* signal handler for SIGCHLD */
	waitpid(WAIT_ANY, NULL, WNOHANG);
}

int main(int argc,  char *argv[])
{
	struct sockaddr_in sockname, client;
	char buffer[80], *ep;
	struct sigaction sa;
	int sd, i;
	int sd_2, i_2; //for making handshake with server!!
	socklen_t clientlen;
	u_short port;
	u_short port_server; //SERVER'S PORT ADDED
	pid_t pid;
	u_long p;
	u_long p_s; //SERVER'S PORT ARGV PART
	struct tls_config *tls_cfg = NULL; /*TLS config*/
	struct tls *tls_ctx = NULL; /*TLS context*/
	struct tls *tls_cctx = NULL; /*client's TLS context*/
	

	/*CLIENT PARTS ADDED*/
	struct sockaddr_in server_sa;
	struct tls_config *tls_cfg2 = NULL; //for getting socket
	struct tls *tls_ctx2 = NULL;
	size_t maxread;
	ssize_t r, rc;
	char buffer2[80];
/*
 * first, figure out what port we will listen on - it should
 * be our first parameter.
 */

	if (argc != 3) /*argc changes from 2 --> 3 */
		usage();
		errno = 0;

	/*Checking proxy's port*/
        p = strtoul(argv[1], &ep, 10);
        if (*argv[1] == '\0' || *ep != '\0') {
		/* parameter wasn't a number, or was empty */
		fprintf(stderr, "%s - not a number\n", argv[1]);
		usage();
	}

	
	/*Checking server's port */
	p_s = strtoul(argv[2], &ep, 10);
	if (*argv[2] == '\0' || *ep != '\0') {
		/* parameter wasn't a number, or was empty */
		fprintf(stderr, "%s - not a number\n", argv[2]);
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
	port = p; /*The port = PROXY'S PORT*/

	port_server = p_s; /*This port = SERVER'S PORT*/

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

	/*printf("THIS PAAAATH: %s", des);
	getcwd(cwd, sizeof(cwd));*/
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
	
	/*Set up TLS certificate authentication to connect with server_solution */
	if (tls_init() == -1)
		errx(1, "unable to initialize TLS");
	if ((tls_cfg2 = tls_config_new()) == NULL)
		errx(1, "unable to allocate TLS config2");
	if (tls_config_set_ca_file(tls_cfg2, des_r) == -1)
		errx(1, "unable to set root CA file2");

	/* the message we send the client!!!!!!!!! --> need to fix this 
 	* bc we dont have access to this  message in proxy */
	
	strlcpy(buffer,
	    "incorrect message is written, this is not from server_solution... \n",
	    sizeof(buffer));
	





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
	printf("PROXY up and listening for connections on proxy's port %u\n", port);



	
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

		if(pid == 0) { /*!!!!!! NEED TO CONNECT WITH SERVER HERE TO GET THE MESSAGE*/
			/*We can only send/write message to client AFTER setting up server!! */
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

			/*we need to read the filename that client wrote us first: */
			ssize_t t;
			char buff_readf[200];
			memset(buff_readf, 0, sizeof(buff_readf));
			if((t = tls_read(tls_cctx, buff_readf, sizeof(buff_readf)-1)) == -1){
				errx(1, "Error: couldn't read client's filename\n");
			}			

			printf("PROXY SIDE FILENAME: %s\n", buff_readf);



			/*set up server connection here bc we successfully accepted socket
 			* and are now ready to set up new socket to give to our server (memset client part)*/
			
			/*first, set up server_sa to be location of the server_solution --> WORKS */
			memset(&server_sa, 0, sizeof(server_sa));
			server_sa.sin_family = AF_INET;
			server_sa.sin_port = htons(port_server);
			
			const char *temp_proxyid = "127.0.0.1";
			server_sa.sin_addr.s_addr = inet_addr(temp_proxyid);
			if (server_sa.sin_addr.s_addr == INADDR_NONE) {
				fprintf(stderr, "Invalid IP address %s\n", temp_proxyid);
				usage();
			}

			/*printf("This is proxy's ip address!!!: %s\n", temp_proxyid);
			*/

			/* NOW, GET A SOCKET*/
			if ((sd_2=socket(AF_INET,SOCK_STREAM,0)) == 1)
				err(1, "socket failed");
			
			/* connect the socket to server_solution described in "server_sa"*/
			if (connect(sd_2, (struct sockaddr *)&server_sa, sizeof(server_sa)) == -1)
				err(1, "connect failed");

			if ((tls_ctx2 = tls_client()) == NULL)
				errx(1, "tls client creation failed");
			if (tls_configure(tls_ctx2, tls_cfg2) == -1)
				errx(1, "tls configuration failed (%s)", tls_error(tls_ctx2));
			if (tls_connect_socket(tls_ctx2, sd_2, "localhost") == -1)
				errx(1, "tls connection failed (%s)", tls_error(tls_ctx2));

			printf("I connected with server_solution!!! %s\n", temp_proxyid);
			do {
				if ((i_2 = tls_handshake(tls_ctx2)) == -1)
					errx(1, "tls handshake failed (%s)", tls_error(tls_ctx2));
			} while(i_2 == TLS_WANT_POLLIN || i_2 == TLS_WANT_POLLOUT);
			
			/*we successfully connected with server_solution. Server_solution 
 			 * will give us the message contents. we need to read that message first*/
		
			
			/*
 * 	 		* finally, we are connected. find out what magnificent wisdom
 * 	 		* our server is going to send to us - since we really don't know
 * 	 		* how much data the server could send to us, we have decided
 * 	 		* we'll stop reading when either our buffer is full, or when
 * 	 		* we get an end of file condition from the read when we read
 * 	 		* 0 bytes - which means that we pretty much assume the server
 * 	 		* is going to send us an entire message, then close the connection
 *       		* to us, so that we see an end-of-file condition on the read.
 * 			* we also make sure we handle EINTR in case we got interrupted
 * 	 		* by a signal.
 *       		*/

			/*We need to send the filename (buff_readf) to server */
			ssize_t w_s;
			ssize_t temp_buflen = strnlen(buff_readf, sizeof(buff_readf));
			if((w_s = tls_write(tls_ctx2, buff_readf, temp_buflen)) != temp_buflen) {
				errx(1, "Failed to write filename message");
			}


			r = -1;
			rc = 0;
			maxread = sizeof(buffer2) - 1; /* leave room for a 0 byte */
			while ((r != 0) && rc < maxread) {
				r = tls_read(tls_ctx2, buffer2 + rc, maxread - rc);
				if (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT)
					continue;
				if (r < 0) {
					err(1, "tls_read failed (%s)", tls_error(tls_ctx2));
				} else
					rc += r;
			}

			/*
 * 	 		 * we must make absolutely sure buffer has a terminating 0 byte
 * 	 	 	 * if we are to use it as a C string
 * 	 	 	 */
			buffer2[rc] = '\0';
			
			printf("Server_SOLUTION sent:  %s",buffer2);
			close(sd_2);







			/*
  			 * write the message to the CLIENT, being sure to
  			 * handle a short write, or being interrupted by
  			 * a signal before we could write anything.
  			 */

			w = 0;
                        written = 0;
                        while (written < strlen(buffer2)) {
                                w = tls_write(tls_cctx, buffer2 + written,
                                    strlen(buffer2) - written);

                                if (w == TLS_WANT_POLLIN || w == TLS_WANT_POLLOUT)
                                        continue;

                                if (w < 0) {
                                        errx(1, "TLS write failed (%s)", tls_error(tls_cctx));
                                }
                                else
                                        written += w;
                        }
                        i = 0;
                        do {
                                i = tls_close(tls_cctx);
                        } while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);

                        close(clientsd);
                        exit(0);








/*
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
			}
			i = 0;
			do {
				i = tls_close(tls_cctx);
			} while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);

			close(clientsd);
			exit(0);
*/		}
		close(clientsd);
	}
}	
