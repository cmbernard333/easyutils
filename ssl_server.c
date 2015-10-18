#include "easy_ssl.h"

int ssl_initialize_server(SSL_CTX *ctx, const char* cipher)
{
	return ssl_initialize_ctx(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, SSL_DEFAULT_PROTOCOL_OPTIONS, cipher);
}