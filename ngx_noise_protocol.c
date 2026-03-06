/*
 * Copyright (C) Maxim Grigoryev
 * Copyright (C) Virgil Security, Inc.
 */

#include "ngx_noise_protocol.h"

typedef struct {
    int pattern_id;
    ngx_flag_t client_needs_local_keypair;
    ngx_flag_t server_needs_local_keypair;
    ngx_flag_t client_needs_remote_public_key;
    ngx_flag_t server_needs_remote_public_key;
} ngx_noise_pattern_capability_t;

static ngx_noise_pattern_capability_t ngx_noise_pattern_capabilities[] = {
    { NOISE_PATTERN_N, 0, 1, 1, 0 },
    { NOISE_PATTERN_X, 1, 1, 1, 0 },
    { NOISE_PATTERN_K, 1, 1, 1, 1 },
    { NOISE_PATTERN_NN, 0, 0, 0, 0 },
    { NOISE_PATTERN_NK, 0, 1, 1, 0 },
    { NOISE_PATTERN_NX, 0, 1, 0, 0 },
    { NOISE_PATTERN_XN, 1, 0, 0, 0 },
    { NOISE_PATTERN_XK, 1, 1, 1, 0 },
    { NOISE_PATTERN_XX, 1, 1, 0, 0 },
    { NOISE_PATTERN_KN, 1, 0, 0, 1 },
    { NOISE_PATTERN_KK, 1, 1, 1, 1 },
    { NOISE_PATTERN_KX, 1, 1, 0, 1 },
    { NOISE_PATTERN_IN, 1, 0, 0, 0 },
    { NOISE_PATTERN_IK, 1, 1, 1, 0 },
    { NOISE_PATTERN_IX, 1, 1, 0, 0 },
};

/* ngx_noise_protocol_next_field 按下划线切分协议名字段。 */
static ngx_int_t ngx_noise_protocol_next_field(const ngx_str_t *name,
        size_t *offset, ngx_str_t *field, ngx_flag_t is_last)
{
    size_t start;

    start = *offset;
    while (*offset < name->len && name->data[*offset] != '_') {
        ++(*offset);
    }

    if (is_last) {
        if (*offset != name->len) {
            return NGX_ERROR;
        }
    } else if (*offset >= name->len) {
        return NGX_ERROR;
    }

    field->data = name->data + start;
    field->len = *offset - start;

    if (!is_last) {
        ++(*offset);
    }

    return field->len == 0 ? NGX_ERROR : NGX_OK;
}

/* ngx_noise_protocol_dh_key_len 返回当前 DH 算法需要的密钥长度。 */
static ngx_int_t ngx_noise_protocol_dh_key_len(int dh_id, size_t *key_len)
{
    switch (dh_id) {
        case NOISE_DH_CURVE25519:
            *key_len = NOISE_PROTOCOL_CURVE25519_KEY_LEN;
            return NGX_OK;
        case NOISE_DH_CURVE448:
            *key_len = NOISE_PROTOCOL_CURVE448_KEY_LEN;
            return NGX_OK;
        default:
            return NGX_ERROR;
    }
}

/* ngx_noise_protocol_get_pattern_capability 返回基础握手模式的能力定义。 */
static ngx_int_t ngx_noise_protocol_get_pattern_capability(int pattern_id,
        const ngx_noise_pattern_capability_t **capability)
{
    size_t i;

    for (i = 0; i < sizeof(ngx_noise_pattern_capabilities)
            / sizeof(ngx_noise_pattern_capabilities[0]); ++i) {
        if (ngx_noise_pattern_capabilities[i].pattern_id == pattern_id) {
            *capability = &ngx_noise_pattern_capabilities[i];
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}

/* ngx_noise_protocol_parse 解析并校验配置中的 Noise suite。 */
ngx_int_t ngx_noise_protocol_parse(ngx_noise_protocol_t *noise_protocol,
        const ngx_str_t *name, const ngx_str_t *prologue)
{
    size_t offset;
    int prefix_id, pattern_id, dh_id, cipher_id, hash_id;
    const ngx_noise_pattern_capability_t *pattern_capability;
    ngx_str_t field;

    if (noise_protocol == NULL || name == NULL || prologue == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(noise_protocol, sizeof(ngx_noise_protocol_t));

    offset = 0;

    if (ngx_noise_protocol_next_field(name, &offset, &field, 0) != NGX_OK) {
        return NGX_ERROR;
    }
    prefix_id = noise_name_to_id(NOISE_PREFIX_CATEGORY,
            (const char *) field.data, field.len);
    if (prefix_id != NOISE_PREFIX_STANDARD) {
        return NGX_ERROR;
    }

    if (ngx_noise_protocol_next_field(name, &offset, &field, 0) != NGX_OK) {
        return NGX_ERROR;
    }
    pattern_id = noise_name_to_id(NOISE_PATTERN_CATEGORY,
            (const char *) field.data, field.len);
    if (ngx_noise_protocol_get_pattern_capability(pattern_id,
            &pattern_capability) != NGX_OK) {
        return NGX_ERROR;
    }
    pattern_id = pattern_capability->pattern_id;

    if (ngx_noise_protocol_next_field(name, &offset, &field, 0) != NGX_OK) {
        return NGX_ERROR;
    }
    dh_id = noise_name_to_id(NOISE_DH_CATEGORY, (const char *) field.data,
            field.len);
    if (ngx_noise_protocol_dh_key_len(dh_id, &noise_protocol->dh_key_len)
            != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_noise_protocol_next_field(name, &offset, &field, 0) != NGX_OK) {
        return NGX_ERROR;
    }
    cipher_id = noise_name_to_id(NOISE_CIPHER_CATEGORY,
            (const char *) field.data, field.len);
    if (cipher_id != NOISE_CIPHER_AESGCM
            && cipher_id != NOISE_CIPHER_CHACHAPOLY) {
        return NGX_ERROR;
    }

    if (ngx_noise_protocol_next_field(name, &offset, &field, 1) != NGX_OK) {
        return NGX_ERROR;
    }
    hash_id = noise_name_to_id(NOISE_HASH_CATEGORY,
            (const char *) field.data, field.len);
    if (hash_id != NOISE_HASH_BLAKE2s && hash_id != NOISE_HASH_BLAKE2b
            && hash_id != NOISE_HASH_SHA256
            && hash_id != NOISE_HASH_SHA512) {
        return NGX_ERROR;
    }

    noise_protocol->name = *name;
    noise_protocol->prologue = *prologue;
    ngx_memzero(&noise_protocol->protocol_id, sizeof(NoiseProtocolId));
    noise_protocol->protocol_id.prefix_id = prefix_id;
    noise_protocol->protocol_id.pattern_id = pattern_id;
    noise_protocol->protocol_id.dh_id = dh_id;
    noise_protocol->protocol_id.hybrid_id = 0;
    noise_protocol->protocol_id.cipher_id = cipher_id;
    noise_protocol->protocol_id.hash_id = hash_id;
    noise_protocol->header.version_id = NOISE_PROTOCOL_VERSION_ID;
    noise_protocol->header.dh_id = (uint8_t) (dh_id & 0xFF);
    noise_protocol->header.cipher_id = (uint8_t) (cipher_id & 0xFF);
    noise_protocol->header.hash_id = (uint8_t) (hash_id & 0xFF);
    noise_protocol->header.pattern_id = (uint8_t) (pattern_id & 0xFF);

    return NGX_OK;
}

/* ngx_noise_protocol_build_prologue 基于当前配置生成动态 prologue 字节串。 */
ngx_int_t ngx_noise_protocol_build_prologue(ngx_pool_t *pool,
        const ngx_noise_protocol_t *noise_protocol, u_char **prologue,
        size_t *prologue_len)
{
    u_char *buf;
    uint16_t header_len;

    if (pool == NULL || noise_protocol == NULL || prologue == NULL
            || prologue_len == NULL) {
        return NGX_ERROR;
    }

    *prologue_len = noise_protocol->prologue.len + sizeof(uint16_t)
            + sizeof(noise_handshake_first_hdr_t);
    buf = ngx_pnalloc(pool, *prologue_len);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    if (noise_protocol->prologue.len != 0) {
        ngx_memcpy(buf, noise_protocol->prologue.data,
                noise_protocol->prologue.len);
    }

    header_len = swapw(sizeof(noise_handshake_first_hdr_t));
    ngx_memcpy(buf + noise_protocol->prologue.len, &header_len,
            sizeof(uint16_t));
    ngx_memcpy(buf + noise_protocol->prologue.len + sizeof(uint16_t),
            &noise_protocol->header, sizeof(noise_handshake_first_hdr_t));

    *prologue = buf;
    return NGX_OK;
}

/* ngx_noise_protocol_match_header 校验协商头是否与当前配置一致。 */
ngx_int_t ngx_noise_protocol_match_header(
        const ngx_noise_protocol_t *noise_protocol,
        const noise_handshake_first_hdr_t *header)
{
    if (noise_protocol == NULL || header == NULL) {
        return NGX_ERROR;
    }

    if (header->version_id != noise_protocol->header.version_id
            || header->dh_id != noise_protocol->header.dh_id
            || header->cipher_id != noise_protocol->header.cipher_id
            || header->hash_id != noise_protocol->header.hash_id
            || header->pattern_id != noise_protocol->header.pattern_id) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ngx_noise_protocol_requires_local_keypair 判断当前角色是否必须提供本端静态私钥。 */
ngx_int_t ngx_noise_protocol_requires_local_keypair(
        const ngx_noise_protocol_t *noise_protocol, ngx_noise_role_e noise_role,
        ngx_flag_t *required)
{
    const ngx_noise_pattern_capability_t *pattern_capability;

    if (noise_protocol == NULL || required == NULL) {
        return NGX_ERROR;
    }

    if (ngx_noise_protocol_get_pattern_capability(
            noise_protocol->protocol_id.pattern_id, &pattern_capability)
            != NGX_OK) {
        return NGX_ERROR;
    }

    switch (noise_role) {
        case NGX_NSOC_CLIENT_ROLE:
            *required = pattern_capability->client_needs_local_keypair;
            return NGX_OK;
        case NGX_NSOC_SERVER_ROLE:
            *required = pattern_capability->server_needs_local_keypair;
            return NGX_OK;
        default:
            return NGX_ERROR;
    }
}

/* ngx_noise_protocol_requires_remote_public_key 判断当前角色是否必须预置对端静态公钥。 */
ngx_int_t ngx_noise_protocol_requires_remote_public_key(
        const ngx_noise_protocol_t *noise_protocol, ngx_noise_role_e noise_role,
        ngx_flag_t *required)
{
    const ngx_noise_pattern_capability_t *pattern_capability;

    if (noise_protocol == NULL || required == NULL) {
        return NGX_ERROR;
    }

    if (ngx_noise_protocol_get_pattern_capability(
            noise_protocol->protocol_id.pattern_id, &pattern_capability)
            != NGX_OK) {
        return NGX_ERROR;
    }

    switch (noise_role) {
        case NGX_NSOC_CLIENT_ROLE:
            *required = pattern_capability->client_needs_remote_public_key;
            return NGX_OK;
        case NGX_NSOC_SERVER_ROLE:
            *required = pattern_capability->server_needs_remote_public_key;
            return NGX_OK;
        default:
            return NGX_ERROR;
    }
}

/* ngx_noise_protocol_init_handshake 用配置好的 suite 和 prologue 初始化握手状态。 */
ngx_int_t ngx_noise_protocol_init_handshake(NOISE_CTX *noise_ctx,
        noise_protocol_conn_t *noise_conn,
        const ngx_noise_protocol_t *noise_protocol, const u_char *prologue,
        size_t prologue_len, ngx_noise_role_e noise_role)
{
    ngx_int_t err;
    NoiseDHState *dh;
    size_t key_len = 0;
    ngx_int_t role;

    if ((noise_role != NGX_NSOC_CLIENT_ROLE)
            && (noise_role != NGX_NSOC_SERVER_ROLE))
        return NGX_ERROR;
    if (noise_init() != NOISE_ERROR_NONE)
        return NGX_ERROR;

    if (noise_protocol == NULL || prologue == NULL) {
        return NGX_ERROR;
    }

    noise_conn->protocol_id = noise_protocol->protocol_id;
    noise_conn->NoisePrologue = (void *) prologue;
    noise_conn->NoisePrologueLen = (ngx_int_t) prologue_len;

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
        dh = noise_handshakestate_get_local_keypair_dh(
                noise_conn->NoiseHandshakeObj);
        key_len = noise_dhstate_get_private_key_length(dh);
        err = noise_dhstate_set_keypair_private(
                dh, noise_ctx->private_keys->elts, key_len);
        if (err != NOISE_ERROR_NONE)
            return NGX_ERROR;
    }

    if (noise_handshakestate_needs_remote_public_key(
            noise_conn->NoiseHandshakeObj)) {
        dh = noise_handshakestate_get_remote_public_key_dh(
                noise_conn->NoiseHandshakeObj);
        key_len = noise_dhstate_get_public_key_length(dh);
        err = noise_dhstate_set_public_key(
                dh, noise_ctx->public_keys->elts, key_len);
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
