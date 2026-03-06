/*
 * Copyright (C) Maxim Grigoryev
 * Copyright (C) Virgil Security, Inc.
 */

#include "ngx_noise_protocol.h"

static ngx_int_t ngx_noise_protocol_next_token(u_char *end, u_char **cursor,
        ngx_str_t *token);
static ngx_flag_t ngx_noise_protocol_token_equals(ngx_str_t *token,
        const char *value, size_t value_len);

static ngx_int_t
ngx_noise_protocol_next_token(u_char *end, u_char **cursor, ngx_str_t *token)
{
    u_char *separator;

    if (*cursor >= end) {
        return NGX_ERROR;
    }

    separator = ngx_strlchr(*cursor, end, '_');
    if (separator == NULL) {
        token->data = *cursor;
        token->len = end - *cursor;
        *cursor = end;

        return NGX_OK;
    }

    token->data = *cursor;
    token->len = separator - *cursor;
    *cursor = separator + 1;

    return NGX_OK;
}

static ngx_flag_t
ngx_noise_protocol_token_equals(ngx_str_t *token, const char *value,
        size_t value_len)
{
    return token->len == value_len
            && ngx_strncmp(token->data, value, value_len) == 0;
}

ngx_int_t
ngx_noise_protocol_parse_name(ngx_str_t *protocol_name,
        ngx_noise_protocol_spec_t *spec)
{
    u_char *cursor;
    u_char *end;
    ngx_str_t token;

    ngx_memzero(spec, sizeof(ngx_noise_protocol_spec_t));

    if (protocol_name->len == 0) {
        return NGX_ERROR;
    }

    spec->name = *protocol_name;
    spec->header.version_id = NOISE_PROTOCOL_VERSION_ID;

    cursor = protocol_name->data;
    end = protocol_name->data + protocol_name->len;

    if (ngx_noise_protocol_next_token(end, &cursor, &token) != NGX_OK
            || !ngx_noise_protocol_token_equals(&token, "Noise",
                    sizeof("Noise") - 1)) {
        return NGX_ERROR;
    }

    if (ngx_noise_protocol_next_token(end, &cursor, &token) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_noise_protocol_token_equals(&token, "NK", sizeof("NK") - 1)) {
        spec->header.pattern_id = (uint8_t) (NOISE_PATTERN_NK & 0xFF);
    } else {
        return NGX_ERROR;
    }

    if (ngx_noise_protocol_next_token(end, &cursor, &token) != NGX_OK
            || !ngx_noise_protocol_token_equals(&token, "25519",
                    sizeof("25519") - 1)) {
        return NGX_ERROR;
    }
    spec->header.dh_id = (uint8_t) (NOISE_DH_CURVE25519 & 0xFF);

    if (ngx_noise_protocol_next_token(end, &cursor, &token) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_noise_protocol_token_equals(&token, "AESGCM",
            sizeof("AESGCM") - 1)) {
        spec->header.cipher_id = (uint8_t) (NOISE_CIPHER_AESGCM & 0xFF);
    } else if (ngx_noise_protocol_token_equals(&token, "ChaChaPoly",
            sizeof("ChaChaPoly") - 1)) {
        spec->header.cipher_id = (uint8_t) (NOISE_CIPHER_CHACHAPOLY & 0xFF);
    } else {
        return NGX_ERROR;
    }

    if (ngx_noise_protocol_next_token(end, &cursor, &token) != NGX_OK
            || cursor != end) {
        return NGX_ERROR;
    }

    if (ngx_noise_protocol_token_equals(&token, "SHA256",
            sizeof("SHA256") - 1)) {
        spec->header.hash_id = (uint8_t) (NOISE_HASH_SHA256 & 0xFF);
    } else if (ngx_noise_protocol_token_equals(&token, "SHA512",
            sizeof("SHA512") - 1)) {
        spec->header.hash_id = (uint8_t) (NOISE_HASH_SHA512 & 0xFF);
    } else if (ngx_noise_protocol_token_equals(&token, "BLAKE2b",
            sizeof("BLAKE2b") - 1)) {
        spec->header.hash_id = (uint8_t) (NOISE_HASH_BLAKE2b & 0xFF);
    } else if (ngx_noise_protocol_token_equals(&token, "BLAKE2s",
            sizeof("BLAKE2s") - 1)) {
        spec->header.hash_id = (uint8_t) (NOISE_HASH_BLAKE2s & 0xFF);
    } else {
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
ngx_noise_protocol_init_prologue(ngx_pool_t *pool, ngx_str_t *prologue_text,
        ngx_noise_protocol_spec_t *spec, ngx_str_t *prologue)
{
    u_char *buffer;

    buffer = ngx_pnalloc(pool,
            prologue_text->len + sizeof(uint16_t)
                    + sizeof(noise_handshake_first_hdr_t));
    if (buffer == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(buffer, prologue_text->data, prologue_text->len);
    ngx_noise_protocol_write_negotiation(buffer + prologue_text->len, spec);

    prologue->data = buffer;
    prologue->len = prologue_text->len + sizeof(uint16_t)
            + sizeof(noise_handshake_first_hdr_t);

    return NGX_OK;
}

ngx_int_t
ngx_noise_protocol_match_header(ngx_noise_protocol_spec_t *spec,
        noise_handshake_first_hdr_t *header)
{
    if (header->version_id != spec->header.version_id) {
        return NGX_ERROR;
    }

    if (header->dh_id != spec->header.dh_id
            || header->cipher_id != spec->header.cipher_id
            || header->hash_id != spec->header.hash_id
            || header->pattern_id != spec->header.pattern_id) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

void
ngx_noise_protocol_write_negotiation(u_char *dst,
        ngx_noise_protocol_spec_t *spec)
{
    *(uint16_t *) (&dst[0]) = swapw(sizeof(noise_handshake_first_hdr_t));
    ngx_memcpy(&dst[sizeof(uint16_t)], &spec->header,
            sizeof(noise_handshake_first_hdr_t));
}

ngx_flag_t
ngx_noise_protocol_needs_local_private_key(ngx_noise_protocol_spec_t *spec,
        ngx_noise_role_e noise_role)
{
    if (spec->header.pattern_id == (uint8_t) (NOISE_PATTERN_NK & 0xFF)) {
        return noise_role == NGX_NSOC_SERVER_ROLE;
    }

    return 0;
}

ngx_flag_t
ngx_noise_protocol_needs_remote_public_key(ngx_noise_protocol_spec_t *spec,
        ngx_noise_role_e noise_role)
{
    if (spec->header.pattern_id == (uint8_t) (NOISE_PATTERN_NK & 0xFF)) {
        return noise_role == NGX_NSOC_CLIENT_ROLE;
    }

    return 0;
}

ngx_int_t ngx_noise_protocol_init_handshake(NOISE_CTX *noise_ctx,
        noise_protocol_conn_t *noise_conn, ngx_noise_protocol_spec_t *spec,
        ngx_str_t *prologue, ngx_noise_role_e noise_role)
{
    ngx_int_t err;
    NoiseDHState *dh;
    size_t key_len = 0;
    ngx_int_t role;
    ngx_str_t *keys;

    if ((noise_role != NGX_NSOC_CLIENT_ROLE)
            && (noise_role != NGX_NSOC_SERVER_ROLE))
        return NGX_ERROR;
    if (noise_init() != NOISE_ERROR_NONE)
        return NGX_ERROR;

    noise_conn->protocol_id.cipher_id = NOISE_ID('C',
            (uint16_t) (spec->header.cipher_id)) & 0xFFFF;
    noise_conn->protocol_id.dh_id = NOISE_ID('D',
            (uint16_t) (spec->header.dh_id)) & 0xFFFF;
    noise_conn->protocol_id.hash_id = NOISE_ID('H',
            (uint16_t) (spec->header.hash_id)) & 0xFFFF;
    noise_conn->protocol_id.hybrid_id = 0;
    noise_conn->protocol_id.pattern_id = NOISE_ID('P',
            (uint16_t) (spec->header.pattern_id)) & 0xFFFF;
    noise_conn->protocol_id.prefix_id = NOISE_PREFIX_STANDARD;

    noise_conn->NoisePrologue = (void *) prologue->data;
    noise_conn->NoisePrologueLen = prologue->len;

    if (noise_role == NGX_NSOC_CLIENT_ROLE) {
        role = NOISE_ROLE_INITIATOR;
    } else {
        role = NOISE_ROLE_RESPONDER;
    }

	err = noise_handshakestate_new_by_id(&noise_conn->NoiseHandshakeObj,
			&noise_conn->protocol_id, role);

    if (err != NOISE_ERROR_NONE)
        return NGX_ERROR;

    err = noise_handshakestate_set_prologue(
            noise_conn->NoiseHandshakeObj, noise_conn->NoisePrologue,
            noise_conn->NoisePrologueLen);
    if (err != NOISE_ERROR_NONE)
        return NGX_ERROR;

    if (noise_handshakestate_needs_local_keypair(
            noise_conn->NoiseHandshakeObj)) {
        if (noise_ctx->private_keys == NULL || noise_ctx->private_keys->nelts == 0) {
            return NGX_ERROR;
        }

        dh = noise_handshakestate_get_local_keypair_dh(
                noise_conn->NoiseHandshakeObj);
        key_len = noise_dhstate_get_private_key_length(dh);
        keys = noise_ctx->private_keys->elts;
        if (keys[0].data == NULL || keys[0].len < key_len) {
            return NGX_ERROR;
        }
        err = noise_dhstate_set_keypair_private(
                dh, keys[0].data, key_len);
        if (err != NOISE_ERROR_NONE)
            return NGX_ERROR;
    }

    if (noise_handshakestate_needs_remote_public_key(
            noise_conn->NoiseHandshakeObj)) {
        if (noise_ctx->public_keys == NULL || noise_ctx->public_keys->nelts == 0) {
            return NGX_ERROR;
        }

        dh = noise_handshakestate_get_remote_public_key_dh(
                noise_conn->NoiseHandshakeObj);
        key_len = noise_dhstate_get_public_key_length(dh);
        keys = noise_ctx->public_keys->elts;
        if (keys[0].data == NULL || keys[0].len < key_len) {
            return NGX_ERROR;
        }
        err = noise_dhstate_set_public_key(
                dh, keys[0].data, key_len);
        if (err != NOISE_ERROR_NONE)
            return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t ngx_noise_protocol_load_private_key(const unsigned char *filename,
        uint8_t *key, size_t len)
{
    FILE *file = fopen((const char *) filename, "rb");
    size_t posn = 0;
    int ch;
    if (len > NOISE_PROTOCOL_MAX_DH_KEY_LEN) {
        return NGX_ERROR;
    }
    if (!file) {
        return NGX_ERROR;
    }
    while ((ch = getc(file)) != EOF) {
        if (posn >= len) {
            fclose(file);
            return NGX_ERROR;
        }
        key[posn++] = (uint8_t) ch;
    }
    if (posn < len) {
        fclose(file);
        return NGX_ERROR;
    }
    fclose(file);
    return NGX_OK;
}

ngx_int_t ngx_noise_protocol_load_public_key(const unsigned char *filename,
        uint8_t *key, size_t len)
{
    FILE *file = fopen((const char *) filename, "rb");
    uint32_t group = 0;
    size_t group_size = 0;
    uint32_t digit = 0;
    size_t posn = 0;
    int ch;
    if (len > NOISE_PROTOCOL_MAX_DH_KEY_LEN) {
        return NGX_ERROR;
    }
    if (!file) {
        return NGX_ERROR;
    }
    while ((ch = getc(file)) != EOF) {
        if (ch >= 'A' && ch <= 'Z') {
            digit = ch - 'A';
        } else if (ch >= 'a' && ch <= 'z') {
            digit = ch - 'a' + 26;
        } else if (ch >= '0' && ch <= '9') {
            digit = ch - '0' + 52;
        } else if (ch == '+') {
            digit = 62;
        } else if (ch == '/') {
            digit = 63;
        } else if (ch == '=') {
            break;
        } else if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') {
            fclose(file);
            return NGX_ERROR;
        }
        group = (group << 6) | digit;
        if (++group_size >= 4) {
            if ((len - posn) < 3) {
                fclose(file);
                return NGX_ERROR;
            }
            group_size = 0;
            key[posn++] = (uint8_t) (group >> 16);
            key[posn++] = (uint8_t) (group >> 8);
            key[posn++] = (uint8_t) group;
        }
    }
    if (group_size == 3) {
        if ((len - posn) < 2) {
            fclose(file);
            return NGX_ERROR;
        }
        key[posn++] = (uint8_t) (group >> 10);
        key[posn++] = (uint8_t) (group >> 2);
    } else if (group_size == 2) {
        if ((len - posn) < 1) {
            fclose(file);
            return NGX_ERROR;
        }
        key[posn++] = (uint8_t) (group >> 4);
    }
    if (posn < len) {
        fclose(file);
        return NGX_ERROR;
    }
    fclose(file);
    return NGX_OK;
}

void ngx_noise_protocol_log_error(ngx_int_t err, char* strObjError,
        ngx_log_t *log, ngx_uint_t log_level)
{
    ngx_int_t result;
    char strerr[30];

    result = noise_strerror(err, strerr, sizeof(strerr));

    if (!result) {
        ngx_log_debug2(
                log_level, log, 0, "NOISE_PROTOCOL %s error: %s", strObjError,
                strerr);
    } else {
        ngx_log_debug0(log_level, log, 0, "NOISE_PROTOCOL error log");
    }

}
