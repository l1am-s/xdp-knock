#include "hmac.h"

#include <string.h>
#include <time.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

bool hmac_is_valid_knock(const uint8_t *payload, const char *secret)
{ // LOOKED UP ONLINE HOW TO DO THE HMAC WITH OPENSSL LIBs
	uint64_t knock_time = 0;
	for (int i = 0; i < KNOCK_TIMESTAMP_SIZE; i++) {
		knock_time = (knock_time << 8) | payload[i];
	}

	time_t current_time = time(NULL);
	int64_t time_diff = (int64_t)current_time - (int64_t)knock_time;
	if (time_diff > KNOCK_MAX_AGE_SEC || time_diff < -KNOCK_MAX_AGE_SEC) {
		return false;
	}

	EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);

	OSSL_PARAM params[2];
	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
	params[1] = OSSL_PARAM_construct_end();

	EVP_MAC_init(ctx, (const unsigned char *)secret, strlen(secret), params);
	EVP_MAC_update(ctx, payload, KNOCK_TIMESTAMP_SIZE);

	uint8_t expected_hmac[32];
	size_t out_len = 0;
	EVP_MAC_final(ctx, expected_hmac, &out_len, sizeof(expected_hmac));

	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(mac);

	const uint8_t *provided_hmac = payload + KNOCK_TIMESTAMP_SIZE;
	return CRYPTO_memcmp(expected_hmac, provided_hmac, 32) == 0;
}
