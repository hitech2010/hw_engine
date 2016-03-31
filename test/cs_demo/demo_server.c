/* A simple SSL echo server */
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

#define CA_LIST "ca-cert.pem"
#define HOST "localhost"
#define PORT 4433
#define BUFSIZE 1024

#define KEYFILE "server-key.pem"
#define CERTFILE "server-cert.pem"
#define PASSWORD "password"

BIO *bio_err = NULL;
static char *pass;
static int s_server_session_id_context = 1;

void echo(SSL *ssl, int s);
int tcp_listen();

/* A simple error and exit routine */
int err_exit(char *string);
int berr_exit(char *string);

int main(int argc, char **argv)
{
	int sock, s;
	BIO *sbio;
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;
	int r;

	if (!bio_err) {
		/* global system initialization*/
		SSL_library_init();
		SSL_load_error_strings();

		/* an error write context*/
		bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	}

	/* create our context */
	meth = TLSv1_server_method();
	ctx = SSL_CTX_new(meth);

	/* load our keys and certificates */
	if (!(SSL_CTX_use_certificate_file(ctx, CERTFILE, SSL_FILETYPE_PEM))) {
		berr_exit("Couldn't read certificate file");
	}

	if (!(SSL_CTX_use_PrivateKey_file(ctx, KEYFILE, SSL_FILETYPE_PEM))) {
		berr_exit("Couldn't read key file");
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		berr_exit("Private key does not match the certificate public key");
	}

	pass = PASSWORD;

	/* Load the CAs we trust */
	if (!SSL_CTX_load_verify_locations(ctx, CA_LIST, 0)) {
		berr_exit("Couldn't read CA list");
	}

	SSL_CTX_set_verify_depth(ctx, 1);

	sock = tcp_listen();
	while(1) {
		if ((s = accept(sock, 0, 0)) < 0)
			err_exit("Problem accepting");

		sbio = BIO_new_socket(s, BIO_NOCLOSE);
		ssl = SSL_new(ctx);
		SSL_set_bio(ssl, sbio, sbio);

		if ((r = SSL_accept(ssl) <= 0))
			berr_exit("SSL accept error");

		echo(ssl, s);
	}

	SSL_CTX_free(ctx);
	exit(0);
}

void echo(SSL *ssl, int s)
{
	char buf[BUFSIZE];
	int r, len, offset;

	while (1) {
		/* First read data */
		r = SSL_read(ssl, buf, BUFSIZE);
		switch(SSL_get_error(ssl, r)) {
		case SSL_ERROR_NONE:
			len = r;
			break;
		case SSL_ERROR_ZERO_RETURN:
			goto end;
		default:
			berr_exit("SSL read problem");
		}

		/* Now keep writing until we've written everything */
		offset = 0;

		while (len) {
			r = SSL_write(ssl, buf+offset, len);
			switch(SSL_get_error(ssl, r)) {
			case SSL_ERROR_NONE:
				len -= r;
				offset += r;
				break;
			default:
				berr_exit("SSL write problem");
			}
		}
	}

end:
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(s);
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

int tcp_listen()
{
	int sock;
	struct sockaddr_in sin;
	int val = 1;

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		err_exit("Couldn't make socket");

	memset(&sin, 0, sizeof(sin));
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_family = AF_INET;
	sin.sin_port=htons(PORT);
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

	if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		berr_exit("Couldn't bind");

	listen(sock, 5);

	return sock;
}
