#ifndef __SSL_COMM_H__
#define __SSL_COMM_H__

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>


typedef enum{
	SSL_OK=0,
	SSL_CLOSE,
	SSL_PRIV_KEY_LOAD_FAILED,
	SSL_PUB_CERT_LOAD_FAILED,
	SSL_CAC_CERT_LOAD_FAILED,
}EASY_SSL_ERROR;

typedef enum {
  PROTOCOL_SSLv2 = 0,
  PROTOCOL_SSLv3,
  PROTOCOL_TLSv1,
  PROTOCOL_TLSv11,
  PROTOCOL_TLSv12
} SSL_PROTOCOL;

static long SSL_DEFAULT_PROTOCOL_OPTIONS=SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1;

/* 
initializes the ssl libraries and error strings
always returns 1;
*/
extern int ssl_initialize_app();
/* 
cleans up ssl libraries and error strings 
*/
extern void ssl_cleanup_app();
/* 
creates an ssl context based on the protocol and provided keys and certs
return 0 if the context was created; otherwise an error code
*/
extern int ssl_ctx_setup(SSL_CTX **_ctx, SSL_PROTOCOL ssl_protocol,
                  const char *ca_path, const char *cert_path,
                  const char *priv_key);
/* 
destroys an ssl context 
*/
extern void ssl_ctx_destroy(SSL_CTX *ctx);
/*
intializes a context with verify options and cipher options
*/
extern int ssl_initialize_ctx(SSL_CTX *ctx, int verify_mode, 
	long options, const char* cipher);
/*
initializes a client context
*/
extern int ssl_intialize_client(SSL_CTX *ctx, const char* cipher);
/*
initializes a server context
*/
extern int ssl_intialize_server(SSL_CTX *ctx, const char* cipher);
/* 
creates an ssl connection to the specified ip and port 
return 0 if the connection was successful; otherwise an error code
*/
extern int ssl_connect(SSL *ssl, SSL_CTX *ssl_ctx, const char *ip, int port);
/* 
creates a strictly bound bio object to the ip and port 
return 0 if the connection was successful; otherwise an error code
*/
extern int ssl_server_bio_strict(SSL **_ssl, SSL_CTX *ctx, const char *ip, int port);
/* 
gets the latest ssl error in the queue 
return 1 if there was an error message; otherwise 0
*/
extern int ssl_get_latest_error_str(SSL* ssl, char **message);
/* 
shuts down and closes an ssl connection 
return 0 if the connection was closed successfully; otherwise error code
*/
extern int ssl_shutdown_and_close(SSL* ssl);
/* 
retrieves the ssl method associated with the given protocol 
return the method associated with the protocol
if the protocol is not found it returns SSLv23_method()
*/
extern SSL_METHOD *ssl_get_protocol_method(SSL_PROTOCOL protocol);

#endif
