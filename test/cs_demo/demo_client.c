/* A simple SSL client.
 * It connects and then forwords data from/to the terminal
 * to/from the server.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define HOST "localhost"
#define PORT 4433
#define BUFSIZE 1024

#define CERTFILE "server-cert.pem"

BIO *bio_err = NULL;

void read_write(SSL *ssl, int sock);

/* A simple error and exit routine */
int err_exit(char *string);
int berr_exit(char *string);

int main(int argc, char **argv)
{
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *sbio;
	X509 *server_cert;
	char *str;
	int sock;

	if (!bio_err) {
		/* global system initialization*/
		SSL_library_init();
		SSL_load_error_strings();

		/* an error write context*/
		bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	}

	/* create our context */
	meth = TLSv1_client_method();
	ctx = SSL_CTX_new(meth);

	sock = tcp_connect();

	/* Connect the SSL socket */
	ssl = SSL_new(ctx);
	sbio = BIO_new_socket(sock, BIO_NOCLOSE);
	SSL_set_bio(ssl, sbio, sbio);

	if (SSL_connect(ssl) <= 0)
		berr_exit("SSL connect error");

	printf("SSL connection using %s\n", SSL_get_cipher(ssl));

	server_cert = SSL_get_peer_certificate(ssl);
	printf("Server certificate:\n");

	str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
	printf("\t subject: %s\n", str);
	OPENSSL_free(str);

	str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
	printf("\t issuer: %s\n", str);
	OPENSSL_free(str);

	/* We could do all sorts of certificate verification stuff here
	 * before deallocating the certificate.
	 */

	X509_free(server_cert);

	read_write(ssl, sock);

	SSL_CTX_free(ctx);

	return 0;
}

int err_exit(char *string)
{
	fprintf(stderr, "%s\n", string);
	exit(0);
}

int berr_exit(char *string)
{
	BIO_printf(bio_err, "%s\n", string);
	ERR_print_errors(bio_err);
	exit(0);
}

int tcp_connect()
{
	struct hostent *hp;
	struct sockaddr_in addr;
	int sock;

	if (!(hp = gethostbyname(HOST)))
		berr_exit("Couldn't resove host");

	memset(&addr, 0, sizeof(addr));
	addr.sin_addr=*(struct in_addr*)hp->h_addr_list[0];
	addr.sin_family=AF_INET;
	addr.sin_port=htons(PORT);

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		err_exit("Could't create socket");

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		err_exit("Couldn't connect socket");

	return sock;
}


/*
 * Read from the keyboard and write to the server
 * Read from the server and write to the keyboard
 * We use select() to multiplex
 */

void read_write(SSL *ssl, int sock)
{
	int width;
	int r, c2sl=0, c2s_offset = 0;
	fd_set readfds, writefds;
	int shutdown_wait = 0;
	char c2s[BUFSIZE], s2c[BUFSIZE];
	int ofcmode;

	/* First we make the socket nonblocking */
	ofcmode = fcntl(sock, F_GETFL, 0);
	ofcmode |= O_NDELAY;
	if (fcntl(sock, F_SETFL, ofcmode))
		err_exit("Couldn't make socket nonblocking");

	width = sock + 1;	// zhjw: highest-numbered fd in readfds or writefds, plus 1
	while (1) {
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);

		FD_SET(sock, &readfds);

		/* If we've still git data to write then don't try to read */
		if (c2sl) {
			FD_SET(sock, &writefds);
		} else {
			FD_SET(fileno(stdin), &readfds);
		}

		r = select(width, &readfds, &writefds, 0, 0);
		if (r = 0)
			continue;

		/* Now check if there is data to read */
		if (FD_ISSET(sock, &readfds)) {
			do {
				r = SSL_read(ssl, s2c, BUFSIZE);

				switch (SSL_get_error(ssl, r)) {
				case SSL_ERROR_NONE:
					fwrite(s2c, 1, r, stdout);
					break;
				case SSL_ERROR_ZERO_RETURN:
					/* End of data */
					if (!shutdown_wait)
						SSL_shutdown(ssl);
					goto end;
					break;
				case SSL_ERROR_WANT_READ:
					break;
				default:
					berr_exit("SSL read problem");
				}
			}while (SSL_pending(ssl));
		}

		/* check for input on the console */
		if (FD_ISSET(fileno(stdin), &readfds)) {
			c2sl = read(fileno(stdin), c2s, BUFSIZE);
			if (c2sl == 0) {
				shutdown_wait = 1;
				if (SSL_shutdown(ssl))
					return;
			}

			c2s_offset = 0;
		}

		/* If we've got data to write then try to write it*/
		if (c2sl && FD_ISSET(sock, &writefds)) {
			r = SSL_write(ssl, c2s + c2s_offset, c2sl);

			switch(SSL_get_error(ssl, r)) {
			case SSL_ERROR_NONE:
				c2sl -= r;
				c2s_offset += r;
				break;

			/* we would have blocked */
			case SSL_ERROR_WANT_WRITE:
				break;

			default:
				berr_exit("SSL write problem");
			}
		}
	}

end:
	SSL_free(ssl);
	close(sock);
	return;
}
