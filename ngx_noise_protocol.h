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
#define NOISE_PROTOCOL_MAX_HANDSHAKE_LEN NOISE_PROTOCOL_CURVE25519_KEY_LEN*2+NOISE_PROTOCOL_MAC_DATA_SIZE*2

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

typedef enum {
    NGX_NSOC_HANDSHAKE_STATUS_OK = 0x00,
    NGX_NSOC_HANDSHAKE_STATUS_VERSION_MISMATCH = 0x01,
    NGX_NSOC_HANDSHAKE_STATUS_NEGOTIATION_MISMATCH = 0x02,
    NGX_NSOC_HANDSHAKE_STATUS_MALFORMED_NEGOTIATION = 0x03,
    NGX_NSOC_HANDSHAKE_STATUS_MALFORMED_HANDSHAKE = 0x04,
    NGX_NSOC_HANDSHAKE_STATUS_PEER_VERIFICATION_FAILED = 0x05,
    NGX_NSOC_HANDSHAKE_STATUS_INTERNAL_ERROR = 0x06
} ngx_nsoc_handshake_status_e;

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

typedef struct ngx_noise_protocol_spec_s {
    ngx_str_t name;
    noise_handshake_first_hdr_t header;
    ngx_flag_t client_needs_local_private_key;
    ngx_flag_t client_needs_remote_public_key;
    ngx_flag_t server_needs_local_private_key;
    ngx_flag_t server_needs_remote_public_key;
} ngx_noise_protocol_spec_t;

typedef struct noise_protocol_conn_s {
        NoiseHandshakeState *NoiseHandshakeObj;
        NoiseCipherState *NoiseSendCipherObj;
        NoiseCipherState *NoiseRecvCipherObj;
        NoiseRandState *NoiseRandObj;
        void *NoisePrologue;
        ngx_int_t NoisePrologueLen;
        NoiseProtocolId protocol_id;
} noise_protocol_conn_t;

#define NOISE_PROTOCOL_VERSION_ID swapw(1)

ngx_int_t ngx_noise_protocol_parse_name(ngx_str_t *protocol_name,
        ngx_noise_protocol_spec_t *spec);
ngx_int_t ngx_noise_protocol_init_prologue(ngx_pool_t *pool,
        ngx_str_t *prologue_text, ngx_noise_protocol_spec_t *spec,
        ngx_str_t *prologue);
ngx_uint_t ngx_noise_protocol_match_header(ngx_noise_protocol_spec_t *spec,
        noise_handshake_first_hdr_t *header);
void ngx_noise_protocol_write_negotiation(u_char *dst,
        ngx_noise_protocol_spec_t *spec);
ngx_flag_t ngx_noise_protocol_needs_local_private_key(
        ngx_noise_protocol_spec_t *spec, ngx_noise_role_e noise_role);
ngx_flag_t ngx_noise_protocol_needs_remote_public_key(
        ngx_noise_protocol_spec_t *spec, ngx_noise_role_e noise_role);
ngx_int_t ngx_noise_protocol_init_handshake(NOISE_CTX *noise_ctx,
        noise_protocol_conn_t *noise_conn, ngx_noise_protocol_spec_t *spec,
        ngx_str_t *prologue, ngx_noise_role_e noise_role);
ngx_int_t ngx_noise_protocol_load_private_key(const unsigned char *filename,
        uint8_t *key, size_t len);
ngx_int_t ngx_noise_protocol_load_public_key(const unsigned char *filename, uint8_t *key,
        size_t len);
const char *ngx_noise_protocol_handshake_status_text(ngx_uint_t status);
void ngx_noise_protocol_log_error(ngx_int_t err, char* strError, ngx_log_t *log,
        ngx_uint_t log_level);
#endif
