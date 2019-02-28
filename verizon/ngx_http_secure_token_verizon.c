#include "ngx_http_secure_token_verizon.h"
#include "../ngx_http_secure_token_filter_module.h"
#include "../ngx_http_secure_token_utils.h"
#include "../ectoken/ectoken_v3.h"

#include <openssl/pem.h>


// typedefs
typedef struct {
	ngx_str_t base_path;
	ngx_str_t key_pair_id;
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
				offsetof(ngx_secure_token_verizon_token_t, key_pair_id),
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

	p = ngx_sprintf(policy.data, POLICY_HEADER, &acl, end_time);
	if (token->ip_address != NULL) {
		p = ngx_sprintf(p, POLICY_CONDITION_IPADDRESS, &ip_address);
	}
	p = ngx_copy(p, POLICY_FOOTER, sizeof(POLICY_FOOTER) - 1);

	policy.len = p - policy.data;

	// sign the policy
	rc = ngx_http_secure_token_sign(r, token->private_key, &policy, &signature);
	if (rc != NGX_OK) {
		return rc;
	}

	// build the token
	p = ngx_pnalloc(
			r->pool,
			sizeof(POLICY_PARAM) - 1 +
			ngx_base64_encoded_length(policy.len) +
			sizeof(SIGNATURE_PARAM) - 1 +
			ngx_base64_encoded_length(signature.len) +
			sizeof(KEY_PAIR_ID_PARAM) - 1 +
			token->key_pair_id.len + 1);
	if (p == NULL) {
		return NGX_ERROR;
	}

	v->data = p;

	p = ngx_copy(p, POLICY_PARAM, sizeof(POLICY_PARAM) - 1);
	p = ngx_encode_base64_verizon(p, &policy);
	p = ngx_copy(p, SIGNATURE_PARAM, sizeof(SIGNATURE_PARAM) - 1);
	p = ngx_encode_base64_verizon(p, &signature);
	p = ngx_copy(p, KEY_PAIR_ID_PARAM, sizeof(KEY_PAIR_ID_PARAM) - 1);
	p = ngx_copy(p, token->key_pair_id.data, token->key_pair_id.len);
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
	if (token->key_pair_id.data == NULL) {
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
