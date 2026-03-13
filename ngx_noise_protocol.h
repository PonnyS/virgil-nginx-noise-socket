/*
 * Copyright (C) Maxim Grigoryev
 * Copyright (C) Virgil Security, Inc.
 */

#ifndef _NGX_NOISE_PROTOCOL_H_INCLUDED_
#define _NGX_NOISE_PROTOCOL_H_INCLUDED_

#include <ngx_core.h>
#include <noise/protocol.h>

#define NOISE_PROTOCOL_CURVE25519_KEY_LEN 32
#define NOISE_PROTOCOL_CURVE448_KEY_LEN 56

#define NOISE_PROTOCOL_MAX_DH_KEY_LEN 2048
#define NOISE_PROTOCOL_PAYLOAD_SIZE 65517
#define NOISE_PROTOCOL_MAC_DATA_SIZE 16
#define NOISE_PROTOCOL_MAX_HANDSHAKE_LEN NOISE_PROTOCOL_CURVE448_KEY_LEN*2+NOISE_PROTOCOL_MAC_DATA_SIZE*2
#define NOISE_PROTOCOL_VERSION_ID swapw(1)
#define NOISE_PROTOCOL_DEFAULT_NAME "Noise_XX_25519_AESGCM_BLAKE2b"
#define NOISE_PROTOCOL_DEFAULT_PROLOGUE "NoiseSocketInit1"

#define swapw(x)((((uint16_t)x & 0xFF00)>>8)| (((uint16_t)x & 0x00FF)<<8))

typedef struct noise_ctx_st {
        ngx_array_t *private_keys;
        ngx_array_t *public_keys;
} NOISE_CTX;

typedef enum {
    NGX_NSOC_UNSET_ROLE = -1,
    NGX_NSOC_CLIENT_ROLE,
    NGX_NSOC_SERVER_ROLE
} ngx_noise_role_e;

#pragma pack(push, 1)
typedef struct noise_handshake_first_hdr_s {
	uint16_t version_id;
	uint8_t dh_id;
	uint8_t cipher_id;
	uint8_t hash_id;
    uint8_t pattern_id;
}noise_handshake_first_hdr_t;

typedef struct noise_handshake_second_hdr_s {
	uint16_t version_id;
	uint8_t status;
}noise_handshake_second_hdr_t;

typedef struct noise_handshake_third_hdr_s {
	uint16_t version_id;
}noise_handshake_third_hdr_t;
#pragma pack (pop)

typedef struct ngx_noise_protocol_s {
        ngx_str_t name;
        ngx_str_t prologue;
        NoiseProtocolId protocol_id;
        noise_handshake_first_hdr_t header;
        size_t dh_key_len;
} ngx_noise_protocol_t;

typedef struct noise_protocol_conn_s {
        NoiseHandshakeState *NoiseHandshakeObj;
        NoiseCipherState *NoiseSendCipherObj;
        NoiseCipherState *NoiseRecvCipherObj;
        NoiseRandState *NoiseRandObj;
        void *NoisePrologue;
        ngx_int_t NoisePrologueLen;
        NoiseProtocolId protocol_id;
} noise_protocol_conn_t;

/* ngx_noise_protocol_parse 解析并校验配置中的 Noise suite。 */
ngx_int_t ngx_noise_protocol_parse(ngx_noise_protocol_t *noise_protocol,
        const ngx_str_t *name, const ngx_str_t *prologue);
/* ngx_noise_protocol_build_prologue 基于当前配置生成动态 prologue 字节串。 */
ngx_int_t ngx_noise_protocol_build_prologue(ngx_pool_t *pool,
        const ngx_noise_protocol_t *noise_protocol, u_char **prologue,
        size_t *prologue_len);
/* ngx_noise_protocol_match_header 校验协商头是否与当前配置一致。 */
ngx_int_t ngx_noise_protocol_match_header(
        const ngx_noise_protocol_t *noise_protocol,
        const noise_handshake_first_hdr_t *header);
/* ngx_noise_protocol_requires_local_keypair 判断当前角色是否必须提供本端静态私钥。 */
ngx_int_t ngx_noise_protocol_requires_local_keypair(
        const ngx_noise_protocol_t *noise_protocol, ngx_noise_role_e noise_role,
        ngx_flag_t *required);
/* ngx_noise_protocol_requires_remote_public_key 判断当前角色是否必须预置对端静态公钥。 */
ngx_int_t ngx_noise_protocol_requires_remote_public_key(
        const ngx_noise_protocol_t *noise_protocol, ngx_noise_role_e noise_role,
        ngx_flag_t *required);
/* ngx_noise_protocol_init_handshake 用配置好的 suite 和 prologue 初始化握手状态。 */
ngx_int_t ngx_noise_protocol_init_handshake(NOISE_CTX *noise_ctx,
        noise_protocol_conn_t *noise_conn,
        const ngx_noise_protocol_t *noise_protocol, const u_char *prologue,
        size_t prologue_len, ngx_noise_role_e noise_role);
ngx_int_t ngx_noise_protocol_load_private_key(const unsigned char *filename,
        uint8_t *key, size_t len);
ngx_int_t ngx_noise_protocol_load_public_key(const unsigned char *filename, uint8_t *key,
        size_t len);
void ngx_noise_protocol_log_error(ngx_int_t err, char* strError, ngx_log_t *log,
        ngx_uint_t log_level);
#endif
