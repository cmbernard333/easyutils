#include "easy_ssl.h"

int ssl_initialize_client(SSL_CTX *ctx, const char* cipher)
{
	return ssl_initialize_ctx(ctx, SSL_VERIFY_PEER, SSL_DEFAULT_PROTOCOL_OPTIONS, cipher);
}