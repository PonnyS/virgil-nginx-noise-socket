/*
 * Copyright (C) Maxim Grigoryev
 * Copyright (C) Virgil Security, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_nsoc.h"

typedef ngx_int_t (*ngx_noise_variable_handler_pt)(ngx_connection_t *c,
        ngx_pool_t *pool, ngx_str_t *s);

static ngx_int_t ngx_nsoc_noiseserver_handler(ngx_nsoc_session_t *s);
static ngx_int_t ngx_nsoc_noiseserver_init_connection(ngx_noise_t *noise,
        ngx_connection_t *c);
static void ngx_nsoc_noiseserver_handshake_handler(ngx_connection_t *c);
static void *ngx_nsoc_noiseserver_create_conf(ngx_conf_t *cf);
static char *ngx_nsoc_noiseserver_merge_conf(ngx_conf_t *cf, void *parent,
        void *child);
static ngx_flag_t ngx_nsoc_noiseserver_has_noise_listener(ngx_conf_t *cf);
static char *ngx_nsoc_noiseserver_load_private_key(ngx_conf_t *cf,
        ngx_noise_t *noise, ngx_str_t *filename);
static char *ngx_nsoc_noiseserver_load_public_key(ngx_conf_t *cf,
        ngx_noise_t *noise, ngx_str_t *filename);

static ngx_int_t ngx_nsoc_noiseserver_init(ngx_conf_t *cf);

static ngx_command_t ngx_nsoc_noiseserver_commands[] =
{

  { ngx_string("noise_handshake_timeout"),
    NGX_NSOC_MAIN_CONF | NGX_NSOC_SRV_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_NSOC_SRV_CONF_OFFSET,
    offsetof(ngx_nsoc_noiseserver_conf_t, handshake_timeout),
    NULL },

  { ngx_string("server_private_key_file"),
    NGX_NSOC_MAIN_CONF | NGX_NSOC_SRV_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_NSOC_SRV_CONF_OFFSET,
    offsetof(ngx_nsoc_noiseserver_conf_t, server_private_key_file),
    NULL },

  { ngx_string("client_public_key_file"),
    NGX_NSOC_MAIN_CONF | NGX_NSOC_SRV_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_NSOC_SRV_CONF_OFFSET,
    offsetof(ngx_nsoc_noiseserver_conf_t, client_public_key_file),
    NULL },

  { ngx_string("noise_protocol"),
    NGX_NSOC_MAIN_CONF | NGX_NSOC_SRV_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_NSOC_SRV_CONF_OFFSET,
    offsetof(ngx_nsoc_noiseserver_conf_t, noise_protocol),
    NULL },

  { ngx_string("noise_prologue"),
    NGX_NSOC_MAIN_CONF | NGX_NSOC_SRV_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_NSOC_SRV_CONF_OFFSET,
    offsetof(ngx_nsoc_noiseserver_conf_t, noise_prologue),
    NULL },

		ngx_null_command
};

static ngx_nsoc_module_t ngx_nsoc_noiseserver_module_ctx =
{ //ngx_nsoc_noiseserver_add_variables, /* preconfiguration */
        NULL,/* preconfiguration */
        ngx_nsoc_noiseserver_init, /* postconfiguration */

        NULL, /* create main configuration */
        NULL, /* init main configuration */

        ngx_nsoc_noiseserver_create_conf, /* create server configuration */
        ngx_nsoc_noiseserver_merge_conf /* merge server configuration */
};

ngx_module_t ngx_nsoc_noiseserver_module =
{
  NGX_MODULE_V1,
  &ngx_nsoc_noiseserver_module_ctx, /* module context */
  ngx_nsoc_noiseserver_commands, /* module directives */
  NGX_NSOC_MODULE, /* module type */
  NULL, /* init master */
  NULL, /* init module */
  NULL, /* init process */
  NULL, /* init thread */
  NULL, /* exit thread */
  NULL, /* exit process */
  NULL, /* exit master */
  NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_nsoc_noiseserver_handler(ngx_nsoc_session_t *s)
{
    ngx_int_t rv;
    ngx_connection_t *c;
    ngx_nsoc_noiseserver_conf_t *noisecf;

    if (!s->noise_on) {
        return NGX_OK;
    }

    c = s->connection;
    noisecf = ngx_nsoc_get_module_srv_conf(s, ngx_nsoc_noiseserver_module);

    if (noisecf->noise == NULL || noisecf->noise->protocol.name.len == 0) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "noise_protocol is not set");

        return NGX_ERROR;
    }

    if (s->server_noise_connection == NULL) {
        c->log->action = "NOISE handshaking";
        rv = ngx_nsoc_noiseserver_init_connection(noisecf->noise, c);

        if (rv != NGX_OK) {
            return rv;
        }
    }

    return NGX_OK;
}

static ngx_flag_t ngx_nsoc_noiseserver_has_noise_listener(ngx_conf_t *cf)
{
    ngx_uint_t i;
    ngx_nsoc_listen_t *listens;
    ngx_nsoc_core_main_conf_t *cmcf;
    ngx_nsoc_core_srv_conf_t *cscf;

    cmcf = ngx_nsoc_conf_get_module_main_conf(cf, ngx_nsoc_core_module);
    cscf = ngx_nsoc_conf_get_module_srv_conf(cf, ngx_nsoc_core_module);
    listens = cmcf->listen.elts;

    for (i = 0; i < cmcf->listen.nelts; i++) {
        if (listens[i].ctx == cscf->ctx && listens[i].noise_on) {
            return 1;
        }
    }

    return 0;
}

static char *ngx_nsoc_noiseserver_load_private_key(ngx_conf_t *cf,
        ngx_noise_t *noise, ngx_str_t *filename)
{
    ngx_array_t *keys;
    ngx_str_t *key;

    if (noise->ctx->private_keys != NULL) {
        return NGX_CONF_OK;
    }

    keys = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
    if (keys == NULL) {
        return NGX_CONF_ERROR;
    }

    key = ngx_array_push(keys);
    if (key == NULL) {
        return NGX_CONF_ERROR;
    }

    key->len = NOISE_PROTOCOL_CURVE25519_KEY_LEN;
    key->data = ngx_pnalloc(cf->pool, NOISE_PROTOCOL_CURVE25519_KEY_LEN);
    if (key->data == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_noise_protocol_load_private_key(
            filename->data, key->data,
            NOISE_PROTOCOL_CURVE25519_KEY_LEN) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                "unable to open server private key file %s", filename->data);
        return NGX_CONF_ERROR;
    }

    noise->ctx->private_keys = keys;
    return NGX_CONF_OK;
}

static char *ngx_nsoc_noiseserver_load_public_key(ngx_conf_t *cf,
        ngx_noise_t *noise, ngx_str_t *filename)
{
    ngx_array_t *keys;
    ngx_str_t *key;

    if (noise->ctx->public_keys != NULL) {
        return NGX_CONF_OK;
    }

    keys = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
    if (keys == NULL) {
        return NGX_CONF_ERROR;
    }

    key = ngx_array_push(keys);
    if (key == NULL) {
        return NGX_CONF_ERROR;
    }

    key->len = NOISE_PROTOCOL_CURVE25519_KEY_LEN;
    key->data = ngx_pnalloc(cf->pool, NOISE_PROTOCOL_CURVE25519_KEY_LEN);
    if (key->data == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_noise_protocol_load_public_key(
            filename->data, key->data,
            NOISE_PROTOCOL_CURVE25519_KEY_LEN) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                "unable to open client public key file %s", filename->data);
        return NGX_CONF_ERROR;
    }

    noise->ctx->public_keys = keys;
    return NGX_CONF_OK;
}

static ngx_int_t ngx_nsoc_noiseserver_init_connection(ngx_noise_t *noise,
        ngx_connection_t *c)
{
    ngx_int_t rc;
    ngx_nsoc_session_t *s;

    s = c->data;

    ngx_log_debug0(
            NGX_LOG_DEBUG_EVENT, c->log, 0,
            "ngx_nsoc_noiseserver_init_connection");

    if (ngx_nsoc_create_connection(noise, c, 0) == NGX_ERROR) {
        return NGX_ERROR;
    }

    rc = ngx_nsoc_handshake(c);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc == NGX_AGAIN) {

        s->server_noise_connection->handler =
                ngx_nsoc_noiseserver_handshake_handler;

        return NGX_AGAIN;
    }

    return NGX_OK;
}

static void ngx_nsoc_noiseserver_handshake_handler(ngx_connection_t *c)
{
    ngx_nsoc_session_t *s;

    s = c->data;

    ngx_log_debug8(
            NGX_LOG_DEBUG_EVENT,
            c->log,
            0,
            "wew status: act:%d dis:%d, rdy:%d eof:%d del:%d peof:%d pos:%d clo:%d",
            c->write->active, c->write->disabled, c->write->ready,
            c->write->eof, c->write->delayed, c->write->pending_eof,
            c->write->posted, c->write->closed);

    ngx_log_debug8(
            NGX_LOG_DEBUG_EVENT,
            c->log,
            0,
            "rew status: act:%d dis:%d, rdy:%d eof:%d del:%d peof:%d pos:%d clo:%d",
            c->read->active, c->read->disabled, c->read->ready, c->read->eof,
            c->read->delayed, c->read->pending_eof, c->read->posted,
            c->read->closed);
    if (!s->server_noise_connection->handshaked) {
        ngx_nsoc_finalize_session(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        return;
    }

    ngx_nsoc_core_run_phases(s);
}

static void *
ngx_nsoc_noiseserver_create_conf(ngx_conf_t *cf)
{
    ngx_nsoc_noiseserver_conf_t *noisecf;

    noisecf = ngx_pcalloc(cf->pool, sizeof(ngx_nsoc_noiseserver_conf_t));
    if (noisecf == NULL) {
        return NULL;
    }

    noisecf->handshake_timeout = NGX_CONF_UNSET_MSEC;

    return noisecf;
}

static char *
ngx_nsoc_noiseserver_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_nsoc_noiseserver_conf_t *prev = parent;
    ngx_nsoc_noiseserver_conf_t *conf = child;
    ngx_nsoc_core_srv_conf_t *cscf;
    ngx_pool_cleanup_t *cln;
    ngx_flag_t requires_noise_protocol;

    ngx_conf_merge_msec_value(
            conf->handshake_timeout, prev->handshake_timeout, 60000);

    ngx_conf_merge_str_value(
            conf->server_private_key_file, prev->server_private_key_file, "");
    ngx_conf_merge_str_value(
            conf->client_public_key_file, prev->client_public_key_file, "");
    ngx_conf_merge_str_value(
            conf->noise_protocol, prev->noise_protocol, "");
    ngx_conf_merge_str_value(
            conf->noise_prologue, prev->noise_prologue, "NoiseSocketInit1");

    conf->noise = ngx_pcalloc(cf->pool, sizeof(ngx_noise_t));
    if (conf->noise == NULL) {
        return NGX_CONF_ERROR ;
    }

    conf->noise->log = cf->log;
    conf->noise->handshake_timeout = conf->handshake_timeout;
    conf->noise->prologue_text = conf->noise_prologue;

    cscf = ngx_nsoc_conf_get_module_srv_conf(cf, ngx_nsoc_core_module);

    if (ngx_nsoc_create(conf->noise, cscf->nsoc_preread_buffer_size, NULL) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "noise server module merge_conf error: unable to create noise ctx");
        return NGX_CONF_ERROR ;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR ;
    }

    cln->handler = ngx_nsoc_cleanup_ctx;
    cln->data = conf->noise;

    requires_noise_protocol = ngx_nsoc_noiseserver_has_noise_listener(cf);
    if (conf->noise_protocol.len == 0) {
        if (requires_noise_protocol) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                    "noise_protocol is required when listen is configured with noise");
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    if (ngx_noise_protocol_parse_name(
            &conf->noise_protocol, &conf->noise->protocol) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "invalid noise protocol %V", &conf->noise_protocol);
        return NGX_CONF_ERROR ;
    }

    if (ngx_noise_protocol_init_prologue(cf->pool,
            &conf->noise_prologue, &conf->noise->protocol,
            &conf->noise->prologue) != NGX_OK) {
        return NGX_CONF_ERROR ;
    }

    if (!requires_noise_protocol) {
        return NGX_CONF_OK;
    }

    if (ngx_noise_protocol_needs_local_private_key(
            &conf->noise->protocol, NGX_NSOC_SERVER_ROLE)) {
        if (conf->server_private_key_file.len == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                    "server_private_key_file is required for %V",
                    &conf->noise->protocol.name);
            return NGX_CONF_ERROR;
        }

        if (ngx_nsoc_noiseserver_load_private_key(
                cf, conf->noise, &conf->server_private_key_file) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_noise_protocol_needs_remote_public_key(
            &conf->noise->protocol, NGX_NSOC_SERVER_ROLE)) {
        if (conf->client_public_key_file.len == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                    "client_public_key_file is required for %V",
                    &conf->noise->protocol.name);
            return NGX_CONF_ERROR;
        }

        if (ngx_nsoc_noiseserver_load_public_key(
                cf, conf->noise, &conf->client_public_key_file) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

static ngx_int_t ngx_nsoc_noiseserver_init(ngx_conf_t *cf)
{
    ngx_nsoc_handler_pt *h;
    ngx_nsoc_core_main_conf_t *cmcf;

    cmcf = ngx_nsoc_conf_get_module_main_conf(cf, ngx_nsoc_core_module);
    cmcf->pool = cf->pool;

    h = ngx_array_push(&cmcf->phases[NGX_NSOC_PROTECT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_nsoc_noiseserver_handler;

    return NGX_OK;
}
