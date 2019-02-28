#include "ngx_http_secure_token_verizon.h"
#include "../ngx_http_secure_token_filter_module.h"
#include "../ngx_http_secure_token_utils.h"
#include "../ectoken/ectoken_v3.h"

#include <openssl/pem.h>

#define POLICY_HEADER "ec_expire=%uD"
#define POLICY_CONDITION_IPADDRESS "&ec_clientip=%V"

// typedefs
typedef struct {
	ngx_str_t base_path;
	ngx_str_t key;
	ngx_http_complex_value_t *ip_address;
	ngx_secure_token_time_t end;
} ngx_secure_token_verizon_token_t;

// globals
static ngx_command_t ngx_http_secure_token_verizon_cmds[] = {
		{ngx_string("base_path"),
				NGX_CONF_TAKE1,
				ngx_conf_set_str_slot,
				0,
				offsetof(ngx_secure_token_verizon_token_t, base_path),
				NULL},

		{ngx_string("key"),
				NGX_CONF_TAKE1,
				ngx_conf_set_str_slot,
				0,
				offsetof(ngx_secure_token_verizon_token_t, key),
				NULL},

		{ngx_string("ip_address"),
				NGX_CONF_TAKE1,
				ngx_http_set_complex_value_slot,
				0,
				offsetof(ngx_secure_token_verizon_token_t, ip_address),
				NULL},

		{ngx_string("end"),
				NGX_CONF_TAKE1,
				ngx_http_secure_token_conf_set_time_slot,
				0,
				offsetof(ngx_secure_token_verizon_token_t, end),
				NULL},
};

static ngx_int_t
ngx_secure_token_verizon_get_var(
	ngx_http_request_t *r,
	ngx_http_variable_value_t *v,
	uintptr_t data) {
	ngx_secure_token_verizon_token_t *token = (void *) data;
	ngx_str_t key;
	ngx_str_t policy;
	ngx_str_t ip_address;
	ngx_int_t rc;
	size_t policy_size;
	time_t end_time;
	u_char *p;

	if (token->ip_address != NULL) {
		if (ngx_http_complex_value(
				r,
				token->ip_address,
				&ip_address) != NGX_OK) {
			return NGX_ERROR;
		}
	}
	// get the end time
	end_time = token->end.val;
	if (token->end.type == NGX_HTTP_SECURE_TOKEN_TIME_RELATIVE) {
		end_time += ngx_time();
	}

	p = ngx_sprintf(policy.data, POLICY_HEADER, end_time);
	if (token->ip_address != NULL) {
		p = ngx_sprintf(p, POLICY_CONDITION_IPADDRESS, &ip_address);
	}

	policy.len = p - policy.data;

//	size_t l_key_len = strlen(token->key);
//	size_t l_string_len = policy.len;
	int l_token_len = (policy.len+(16*2))*4;
	char l_token[l_token_len];
	int l_ret = ectoken_encrypt_token(l_token, &l_token_len,
									  policy.data, policy.len,
									  token->key, token->key.len);
	if (l_ret < 0)
	{
		return NGX_ERROR;
	}

	printf("%s\n", l_token);

	// build the token
	p = ngx_pnalloc(
			r->pool,
			ngx_base64_encoded_length(l_token));
	if (p == NULL) {
		return NGX_ERROR;
	}

	v->data = p;

	p = ngx_encode_base64(p, &l_token);
	*p = '\0';

	v->len = p - v->data;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	return NGX_OK;
}

char *
ngx_secure_token_verizon_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_secure_token_verizon_token_t *token;
	char *rv;

	// init config
	token = ngx_pcalloc(cf->pool, sizeof(*token));
	if (token == NULL) {
		return NGX_CONF_ERROR;
	}

	token->end.type = NGX_HTTP_SECURE_TOKEN_TIME_UNSET;

	// parse the block
	rv = ngx_http_secure_token_conf_block(
			cf,
			ngx_http_secure_token_verizon_cmds,
			token,
			ngx_secure_token_verizon_get_var);
	if (rv != NGX_CONF_OK) {
		return rv;
	}

	// validate required params
	if (token->key.data == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						   "\"key\" is mandatory for verizon tokens");
		return NGX_CONF_ERROR;
	}

	// populate unset optional params
	if (token->end.type == NGX_HTTP_SECURE_TOKEN_TIME_UNSET) {
		token->end.type = NGX_HTTP_SECURE_TOKEN_TIME_RELATIVE;
		token->end.val = 86400;
	}

	return NGX_CONF_OK;
}
