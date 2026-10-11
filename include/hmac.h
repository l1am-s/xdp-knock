#ifndef HMAC_H
#define HMAC_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define KNOCK_TIMESTAMP_SIZE 8
#define KNOCK_HMAC_SIZE 32 // always the output length of sha-256 hmac
#define KNOCK_PAYLOAD_SIZE (KNOCK_TIMESTAMP_SIZE + KNOCK_HMAC_SIZE)

#define KNOCK_MAX_AGE_SEC 5

bool hmac_is_valid_knock(const uint8_t *payload, const char *secret);

#endif