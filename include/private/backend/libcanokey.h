#ifndef CNK_BACKEND_LIBCANOKEY_H
#define CNK_BACKEND_LIBCANOKEY_H

#include "pkcs11.h"
#include <stddef.h>
#include <stdint.h>

typedef struct CNK_LIBCANO_OPERATION CNK_LIBCANO_OPERATION;
typedef struct CNK_LIBCANO_CONTEXT CNK_LIBCANO_CONTEXT;
typedef struct {
  uint32_t struct_size;
  uint32_t kind, phase, reference, presence_flags;
  uint16_t status_word;
  uint8_t retries_remaining, reserved;
} CNK_LIBCANO_ERROR;
typedef struct {
  uint32_t struct_size, flags, max_command_bytes, max_response_bytes, max_total_response_bytes, max_exchanges;
} CNK_LIBCANO_OPTIONS;

enum { CNK_LIBCANO_OK = 0, CNK_LIBCANO_STEP_EXCHANGE = 1, CNK_LIBCANO_STEP_DONE = 2 };
enum { CNK_LIBCANO_CONTEXT_SELECTED = 1, CNK_LIBCANO_CONTEXT_PIN_VERIFIED = 2 };
enum {
  CNK_LIBCANO_INVALID_ARGUMENT = 1,
  CNK_LIBCANO_INVALID_STATE = 2,
  CNK_LIBCANO_BUFFER_TOO_SMALL = 3,
  CNK_LIBCANO_RESULT_TYPE_MISMATCH = 4,
  CNK_LIBCANO_PROTOCOL_ERROR = 5,
  CNK_LIBCANO_PANIC = 6,
};
enum {
  CNK_LIBCANO_ERROR_AUTHENTICATION_FAILED = 6,
  CNK_LIBCANO_ERROR_PIN_BLOCKED = 7,
  CNK_LIBCANO_ERROR_NOT_FOUND = 10,
  CNK_LIBCANO_ERROR_UNSUPPORTED_FEATURE = 12,
  CNK_LIBCANO_ERROR_LIMIT_EXCEEDED = 5,
};
struct CNK_PKCS11_SESSION;
CK_RV cnk_ensure_libcanokey_profile(struct CNK_PKCS11_SESSION *session);
enum {
  CNK_LIBCANO_ALG_RSA_2048 = 2,
  CNK_LIBCANO_ALG_RSA_3072 = 3,
  CNK_LIBCANO_ALG_RSA_4096 = 4,
  CNK_LIBCANO_ALG_P256 = 5,
  CNK_LIBCANO_ALG_P384 = 6,
  CNK_LIBCANO_ALG_P521 = 7,
  CNK_LIBCANO_ALG_SECP256K1 = 8,
  CNK_LIBCANO_ALG_ED25519 = 10,
  CNK_LIBCANO_ALG_X25519 = 11,
  CNK_LIBCANO_ALG_MLDSA65 = 12,
  CNK_LIBCANO_ALG_MLKEM768 = 13,
};
enum {
  CNK_LIBCANO_SIGN_RSA_BLOCK = 1,
  CNK_LIBCANO_SIGN_DIGEST = 2,
  CNK_LIBCANO_SIGN_MESSAGE = 3,
};

uint32_t cnk_piv_context_new(const void *, uint32_t, CNK_LIBCANO_CONTEXT **, CNK_LIBCANO_ERROR *);
void cnk_piv_context_free(CNK_LIBCANO_CONTEXT *);
uint32_t cnk_piv_get_metadata_in_context_new(const CNK_LIBCANO_CONTEXT *, uint32_t, const CNK_LIBCANO_OPTIONS *,
                                             CNK_LIBCANO_OPERATION **, CNK_LIBCANO_ERROR *);
uint32_t cnk_piv_read_certificate_in_context_new(const CNK_LIBCANO_CONTEXT *, uint32_t, const CNK_LIBCANO_OPTIONS *,
                                                 CNK_LIBCANO_OPERATION **, CNK_LIBCANO_ERROR *);
uint32_t cnk_piv_sign_in_context_new(const CNK_LIBCANO_CONTEXT *, uint32_t, uint32_t, uint32_t, const uint8_t *, size_t,
                                     const CNK_LIBCANO_OPTIONS *, CNK_LIBCANO_OPERATION **, CNK_LIBCANO_ERROR *);
uint32_t cnk_piv_sign_streaming_in_context_new(const CNK_LIBCANO_CONTEXT *, uint32_t, uint32_t, const uint8_t *, size_t,
                                               const uint8_t *, size_t, const CNK_LIBCANO_OPTIONS *,
                                               CNK_LIBCANO_OPERATION **, CNK_LIBCANO_ERROR *);
uint32_t cnk_piv_read_object_in_context_new(const CNK_LIBCANO_CONTEXT *, const uint8_t *, size_t,
                                            const CNK_LIBCANO_OPTIONS *, CNK_LIBCANO_OPERATION **, CNK_LIBCANO_ERROR *);
uint32_t cnk_piv_decrypt_in_context_new(const CNK_LIBCANO_CONTEXT *, uint32_t, uint32_t, const uint8_t *, size_t,
                                        const CNK_LIBCANO_OPTIONS *, CNK_LIBCANO_OPERATION **, CNK_LIBCANO_ERROR *);
uint32_t cnk_piv_derive_in_context_new(const CNK_LIBCANO_CONTEXT *, uint32_t, uint32_t, const uint8_t *, size_t,
                                       const CNK_LIBCANO_OPTIONS *, CNK_LIBCANO_OPERATION **, CNK_LIBCANO_ERROR *);
uint32_t cnk_piv_decapsulate_in_context_new(const CNK_LIBCANO_CONTEXT *, uint32_t, const uint8_t *, size_t,
                                            const CNK_LIBCANO_OPTIONS *, CNK_LIBCANO_OPERATION **, CNK_LIBCANO_ERROR *);
uint32_t cnk_operation_start(CNK_LIBCANO_OPERATION *, uint32_t *, CNK_LIBCANO_ERROR *);
uint32_t cnk_operation_advance(CNK_LIBCANO_OPERATION *, const uint8_t *, size_t, uint32_t *, CNK_LIBCANO_ERROR *);
uint32_t cnk_operation_command(const CNK_LIBCANO_OPERATION *, uint8_t *, size_t *);
uint32_t cnk_operation_result_copy_bytes(const CNK_LIBCANO_OPERATION *, uint8_t *, size_t *);
uint32_t cnk_operation_signature_p1363(const CNK_LIBCANO_OPERATION *, uint8_t *, size_t *);
uint32_t cnk_operation_signature_der(const CNK_LIBCANO_OPERATION *, uint8_t *, size_t *);
uint32_t cnk_operation_signature_encoding(const CNK_LIBCANO_OPERATION *, uint32_t *);
uint32_t cnk_operation_error(const CNK_LIBCANO_OPERATION *, CNK_LIBCANO_ERROR *);
void cnk_operation_free(CNK_LIBCANO_OPERATION *);

#endif
