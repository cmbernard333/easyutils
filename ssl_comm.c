#include <stdio.h>
#include <stdlib.h>
#include "easy_ssl.h"

#ifndef MS_CALLBACK
#define MS_CALLBACK
#endif

extern int MS_CALLBACK verify_callback(int ok, X509_STORE_CTX *ctx);

int ssl_initialize_app()
{
	SSL_load_error_strings();
	SSL_library_init();
	ERR_load_crypto_strings();
	return 1;
}

void ssl_cleanup_app()
{
	FIPS_mode_set(0);
	ERR_remove_state();
	ERR_free_strings();
}

int ssl_ctx_setup(SSL_CTX **_ctx, SSL_PROTOCOL ssl_protocol,
                  const char *ca_path, 
                  const char *cert_path, 
                  const char *priv_key)
{
	SSL_CTX* ctx = NULL;
	SSL_METHOD* meth = NULL;

	/* initialize context */
	meth = ssl_get_protocol_method(ssl_protocol);
	ctx = SSL_CTX_new(meth);

	/* load key, certificate, and certificate chain file */
	if(!SSL_CTX_use_PrivateKey_file(ctx,priv_key,SSL_FILETYPE_PEM))
	{
		/* TODO: log error */
		return SSL_PRIV_KEY_LOAD_FAILED;
	}
	if(!SSL_CTX_use_certificate_file(ctx,cert_path,SSL_FILETYPE_PEM))
	{
		/* TODO: log error */
		return SSL_PUB_CERT_LOAD_FAILED;
	}
	if(!SSL_CTX_use_certificate_chain_file(ctx,ca_path))
	{
		/* TODO: log error */
		return SSL_CAC_CERT_LOAD_FAILED;
	}
	if(!SSL_CTX_load_verify_locations(ctx,ca_path,NULL))
	{
		/* TODO: log error */
		return SSL_CAC_CERT_LOAD_FAILED;
	}
	*_ctx = ctx;

	return 0;
}

int ssl_initialize_ctx(SSL_CTX *ctx, int mode, long options, const char* cipher)
{
	SSL_CTX_set_verify(ctx, mode, verify_callback);
	SSL_CTX_set_verify_depth(ctx,4);
	SSL_CTX_set_options(ctx, options);
	if(!(SSL_CTX_get_options(ctx) & options))
	{
		/* TODO: log error - could not set options */
		return 1;
	}
	if(!SSL_CTX_set_cipher_list(ctx, cipher))
	{
		/* TODO : log error - could not set cipher list */
		return 1;
	}
	return 0;
}

void ssl_ctx_destroy(SSL_CTX *ctx)
{
	SSL_CTX_free(ctx);
}

int ssl_get_latest_error_str(SSL* ssl, char **message)
{
	/*
		Compose an error message using the three errors in SSL
		Library
		Function
		Error

		ssl_get_error() should be called prior to this

		const char *ERR_lib_error_string(unsigned long e); library in error 
  		const char *ERR_func_error_string(unsigned long e); function in error 
 		const char *ERR_reason_error_string(unsigned long e); reason for error 

 		void ERR_error_string_n(unsigned long e, char *buf, size_t len)
	*/
	unsigned long q = 0;
	const char *lib_err = NULL;
	const char *func_err = NULL;
	const char *rea_err = NULL;

	if( (q = ERR_get_error()) !=0 )
	{
		lib_err = ERR_lib_error_string(q);
		func_err = ERR_func_error_string(q);
		rea_err = ERR_reason_error_string(q);

		/* manually allocate space for error */
		*message = (char*)calloc(1,120*sizeof(char));
		if(*message)
		{
			return -1;
		}
		sprintf(&message,"err->0x%08x:%s:%s:%s",q ,lib_err,func_err,rea_err);
	} 
	else
	{
		return 0;
	}
	return 1;
}

SSL_METHOD *ssl_get_protocol_method(SSL_PROTOCOL protocol)
{
	SSL_METHOD* method = NULL;
	switch(protocol)
	{
		case PROTOCOL_SSLv2:
  		case PROTOCOL_SSLv3:
  			method = SSLv23_method();
  			break;
  		case PROTOCOL_TLSv1:
  			method = TLSv1_method();
  			break;
  		case PROTOCOL_TLSv11:
  			method = TLSv11_method();
  			break;
  		case PROTOCOL_TLSv12:
  			method = TLSv12_method();
  			break;
  		default:
  			method = SSLv23_method();
  			break;
	}
	return method;
}

int MS_CALLBACK verify_callback(int ok, X509_STORE_CTX *ctx)
{
    char buf[256];
    X509 *err_cert;
    int err, depth;

    FILE* bio_err;

    if(bio_err==NULL)
    {
    	bio_err = BIO_new_fp(stderr,BIO_NOCLOSE);
    }
    
    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);
    
    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, sizeof buf);
    BIO_printf(bio_err, "depth=%d %s\n", depth, buf);
    if (!ok) {
        BIO_printf(bio_err, "verify error:num=%d:%s\n", err,
                   X509_verify_cert_error_string(err));
        /*
        if (verify_depth >= depth) {
            ok = 1;
            verify_error = X509_V_OK;
        } else { 
            ok = 0;
            verify_error = X509_V_ERR_CERT_CHAIN_TOO_LONG;
        }   
        */
    }       
    switch (ctx->error) {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buf,
                          sizeof buf);
        BIO_printf(bio_err, "issuer= %s\n", buf);
        break;            
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
        BIO_printf(bio_err, "notBefore=");
        ASN1_TIME_print(bio_err, X509_get_notBefore(ctx->current_cert));
        BIO_printf(bio_err, "\n");
        break;
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
        BIO_printf(bio_err, "notAfter=");
        ASN1_TIME_print(bio_err, X509_get_notAfter(ctx->current_cert));
        BIO_printf(bio_err, "\n");
        break;
    }   
    BIO_printf(bio_err, "verify return:%d\n", ok);
    return (ok);
}