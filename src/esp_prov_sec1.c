/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Protocomm security scheme 1 -- adapted from ESP-IDF security1.c (Apache-2.0).
 */

#include "esp_prov_internal.h"
#include "esp_prov_pb.h"

#include <errno.h>
#include <string.h>

#include <mbedtls/constant_time.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/private/aes.h>
#include <mbedtls/private/bignum.h>
#include <mbedtls/private/ecp.h>
#include <mbedtls/private/sha256.h>

#include <psa/crypto.h>

#include <zephyr/autoconf.h>
#include <zephyr/logging/log.h>

LOG_MODULE_DECLARE(esp_prov_session);

/* mbedtls_ctr_drbg_random negative code when CTR_DRBG is not built (TF-PSA sample prj). */
#define SEC1_DRBG_REQUEST_FAIL (-0x003C)

/* Single PSA RNG path for both transports (mutex covers all sec1 use). */
static K_MUTEX_DEFINE(sec1_crypto_mu);

#define PUBLIC_KEY_LEN 32U
#define RAND_LEN       16U

#define ST_CMD0 0U
#define ST_CMD1 1U
#define ST_DONE 2U

#define SEC1_CMD0 0U
#define SEC1_CMD1 2U

struct esp_prov_sec1 {
	uint32_t sid;
	uint8_t st;
	uint8_t dev_pub[PUBLIC_KEY_LEN];
	uint8_t cli_pub[PUBLIC_KEY_LEN];
	uint8_t sym_key[PUBLIC_KEY_LEN];
	uint8_t rand[RAND_LEN];
	mbedtls_aes_context aes;
	unsigned char stb[16];
	size_t nc_off;
};

static struct esp_prov_sec1 stor_http;
static struct esp_prov_sec1 stor_ble;

static bool s_rng_ok;

esp_prov_sec1_t *esp_prov_sec1_http(void)
{
	return &stor_http;
}

esp_prov_sec1_t *esp_prov_sec1_ble(void)
{
	return &stor_ble;
}

static void flip_endian(uint8_t *data, size_t len)
{
	for (size_t i = 0U; i < len / 2U; i++) {
		uint8_t t = data[i];

		data[i] = data[len - 1U - i];
		data[len - 1U - i] = t;
	}
}

static int drbg_random(void *ctx, unsigned char *out, size_t len)
{
	psa_status_t st;

	(void)ctx;
	st = psa_generate_random(out, len);
	return (st == PSA_SUCCESS) ? 0 : SEC1_DRBG_REQUEST_FAIL;
}

/*
 * TF-PSA 1.0 (Zephyr 4.4) does not emit legacy mbedtls_entropy_* when MBEDTLS_ENTROPY_C is
 * absent/stubbed; use PSA (psa_crypto_init + psa_generate_random). Do not seed from
 * sys_csrand_get() alone — that previously regressed ECDH (ecdh_gen_public failure).
 */
static int rng_ensure(void)
{
	psa_status_t st;

	if (s_rng_ok) {
		return 0;
	}

	for (unsigned attempt = 0U; attempt < 10U; attempt++) {
		st = psa_crypto_init();
		if (st == PSA_SUCCESS || st == PSA_ERROR_ALREADY_EXISTS) {
			s_rng_ok = true;
			return 0;
		}

		LOG_ERR("psa_crypto_init %d (attempt %u/10)", (int)st, attempt + 1U);
		k_msleep(20);
	}

	return -EIO;
}

static void sec1_reset_nolock(esp_prov_sec1_t *ctx)
{
	if (ctx == NULL) {
		return;
	}
	if (ctx->st == ST_DONE) {
		mbedtls_aes_free(&ctx->aes);
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->sid = 0xffffffffU;
	ctx->st = ST_CMD0;
}

void esp_prov_sec1_reset(esp_prov_sec1_t *ctx)
{
	if (ctx == NULL) {
		return;
	}
	k_mutex_lock(&sec1_crypto_mu, K_FOREVER);
	sec1_reset_nolock(ctx);
	k_mutex_unlock(&sec1_crypto_mu);
}

static int sec1_transport_close_nolock(esp_prov_sec1_t *ctx, uint32_t session_id)
{
	if (ctx == NULL || ctx->sid != session_id) {
		return -EINVAL;
	}
	sec1_reset_nolock(ctx);
	return 0;
}

int esp_prov_sec1_rng_prewarm(void)
{
	int err;

	k_mutex_lock(&sec1_crypto_mu, K_FOREVER);
	err = rng_ensure();
	k_mutex_unlock(&sec1_crypto_mu);
	return (err == 0) ? 0 : -EIO;
}

int esp_prov_sec1_transport_open(esp_prov_sec1_t *ctx, uint32_t session_id)
{
	if (ctx == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&sec1_crypto_mu, K_FOREVER);
	if (rng_ensure() != 0) {
		k_mutex_unlock(&sec1_crypto_mu);
		return -EIO;
	}
	if (ctx->sid != 0xffffffffU && ctx->sid != session_id) {
		(void)sec1_transport_close_nolock(ctx, ctx->sid);
	}
	if (ctx->st == ST_DONE) {
		mbedtls_aes_free(&ctx->aes);
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->sid = session_id;
	ctx->st = ST_CMD0;
	k_mutex_unlock(&sec1_crypto_mu);
	return 0;
}

int esp_prov_sec1_transport_close(esp_prov_sec1_t *ctx, uint32_t session_id)
{
	int r;

	k_mutex_lock(&sec1_crypto_mu, K_FOREVER);
	r = sec1_transport_close_nolock(ctx, session_id);
	k_mutex_unlock(&sec1_crypto_mu);
	return r;
}

static int handle_cmd0(esp_prov_sec1_t *s, const uint8_t *inner, size_t inner_len, const char *pop,
		       uint8_t *sec1_out, size_t sec1_cap, size_t *sec1_olen)
{
	if (s->st != ST_CMD0) {
		if (s->st == ST_DONE) {
			mbedtls_aes_free(&s->aes);
		}
		s->st = ST_CMD0;
	}

	if (esp_prov_pb_parse_sc0(inner, inner_len, s->cli_pub) != 0) {
		return -EINVAL;
	}

	mbedtls_ecp_group grp;
	mbedtls_ecp_point Q, Qp;
	mbedtls_mpi d, z;
	int err;

	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&Q);
	mbedtls_ecp_point_init(&Qp);
	mbedtls_mpi_init(&d);
	mbedtls_mpi_init(&z);

	err = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
	if (err != 0) {
		LOG_ERR("ecp_group_load %d", err);
		err = -EIO;
		goto out;
	}

	err = mbedtls_ecdh_gen_public(&grp, &d, &Q, drbg_random, NULL);
	if (err != 0) {
		LOG_ERR("ecdh_gen_public %d", err);
		err = -EIO;
		goto out;
	}

	size_t wlen = 0U;

	err = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &wlen, s->dev_pub,
					     sizeof(s->dev_pub));
	if (err != 0 || wlen != PUBLIC_KEY_LEN) {
		LOG_ERR("write_binary dev %d", err);
		err = -EIO;
		goto out;
	}

	err = mbedtls_ecp_point_read_binary(&grp, &Qp, s->cli_pub, PUBLIC_KEY_LEN);
	if (err != 0) {
		LOG_ERR("read_binary cli %d", err);
		err = -EINVAL;
		goto out;
	}

	err = mbedtls_ecdh_compute_shared(&grp, &z, &Qp, &d, drbg_random, NULL);
	if (err != 0) {
		if (err == PSA_ERROR_INSUFFICIENT_MEMORY) {
			LOG_ERR("compute_shared: PSA OOM (-141) during ECDH -- raise "
				"CONFIG_HEAP_MEM_POOL_SIZE or reduce Wi-Fi/MQTT/other heap use");
		} else {
			LOG_ERR("compute_shared %d", err);
		}
		err = -EIO;
		goto out;
	}

	err = mbedtls_mpi_write_binary(&z, s->sym_key, PUBLIC_KEY_LEN);
	if (err != 0) {
		err = -EIO;
		goto out;
	}
	flip_endian(s->sym_key, PUBLIC_KEY_LEN);

	if (pop != NULL && pop[0] != '\0') {
		uint8_t sha[32];

		mbedtls_sha256((const unsigned char *)pop, strlen(pop), sha, 0);
		for (size_t i = 0U; i < PUBLIC_KEY_LEN; i++) {
			s->sym_key[i] ^= sha[i];
		}
	}

	err = drbg_random(NULL, s->rand, RAND_LEN);
	if (err != 0) {
		err = -EIO;
		goto out;
	}

	if (esp_prov_pb_build_sr0(sec1_out, sec1_cap, sec1_olen, s->dev_pub, s->rand) != 0) {
		err = -EINVAL;
		goto out;
	}
	s->st = ST_CMD1;
	err = 0;

out:
	mbedtls_mpi_free(&z);
	mbedtls_mpi_free(&d);
	mbedtls_ecp_point_free(&Qp);
	mbedtls_ecp_point_free(&Q);
	mbedtls_ecp_group_free(&grp);
	return err;
}

static int handle_cmd1(esp_prov_sec1_t *s, const uint8_t *inner, size_t inner_len, uint8_t *sec1_out,
		       size_t sec1_cap, size_t *sec1_olen)
{
	const uint8_t *verify = NULL;
	size_t verify_len = 0U;

	if (s->st != ST_CMD1) {
		LOG_WRN("cmd1 bad state %u", s->st);
		return -EINVAL;
	}

	if (esp_prov_pb_parse_sc1(inner, inner_len, &verify, &verify_len) != 0) {
		return -EINVAL;
	}
	if (verify_len != PUBLIC_KEY_LEN) {
		return -EINVAL;
	}

	mbedtls_aes_init(&s->aes);
	memset(s->stb, 0, sizeof(s->stb));
	s->nc_off = 0U;

	int mbed_err = mbedtls_aes_setkey_enc(&s->aes, s->sym_key, (int)sizeof(s->sym_key) * 8);

	if (mbed_err != 0) {
		mbedtls_aes_free(&s->aes);
		return -EIO;
	}

	uint8_t check[PUBLIC_KEY_LEN];

	mbed_err = mbedtls_aes_crypt_ctr(&s->aes, PUBLIC_KEY_LEN, &s->nc_off, s->rand, s->stb, verify,
					 check);
	if (mbed_err != 0) {
		mbedtls_aes_free(&s->aes);
		return -EIO;
	}

	if (mbedtls_ct_memcmp(check, s->dev_pub, PUBLIC_KEY_LEN) != 0) {
		LOG_WRN("sec1 verifier mismatch");
		mbedtls_aes_free(&s->aes);
		return -EPERM;
	}

	uint8_t outbuf[PUBLIC_KEY_LEN];

	mbed_err = mbedtls_aes_crypt_ctr(&s->aes, PUBLIC_KEY_LEN, &s->nc_off, s->rand, s->stb, s->cli_pub,
					 outbuf);
	if (mbed_err != 0) {
		mbedtls_aes_free(&s->aes);
		return -EIO;
	}

	if (esp_prov_pb_build_sr1(sec1_out, sec1_cap, sec1_olen, outbuf) != 0) {
		mbedtls_aes_free(&s->aes);
		return -EINVAL;
	}

	s->st = ST_DONE;
	return 0;
}

int esp_prov_sec1_process_session(esp_prov_sec1_t *ctx, const uint8_t *req, size_t req_len,
				  const char *pop, uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
	uint32_t sec_ver = 0U;
	uint32_t sec1_msg = 0U;
	const uint8_t *inner = NULL;
	size_t inner_len = 0U;
	uint8_t sec1buf[192];
	size_t sec1olen = 0U;
	int err;

	if (ctx == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&sec1_crypto_mu, K_FOREVER);

	if (esp_prov_pb_parse_session_request(req, req_len, &sec_ver, &sec1_msg, &inner,
					      &inner_len) != 0) {
		k_mutex_unlock(&sec1_crypto_mu);
		return -EINVAL;
	}
	if (sec_ver != 1U) {
		k_mutex_unlock(&sec1_crypto_mu);
		return -EINVAL;
	}

	if (sec1_msg == SEC1_CMD0) {
		err = handle_cmd0(ctx, inner, inner_len, pop, sec1buf, sizeof(sec1buf), &sec1olen);
	} else if (sec1_msg == SEC1_CMD1) {
		err = handle_cmd1(ctx, inner, inner_len, sec1buf, sizeof(sec1buf), &sec1olen);
	} else {
		k_mutex_unlock(&sec1_crypto_mu);
		return -EINVAL;
	}

	if (err != 0) {
		k_mutex_unlock(&sec1_crypto_mu);
		return err;
	}

	if (esp_prov_pb_build_session_response(resp, resp_cap, resp_len, sec_ver, sec1buf,
					       sec1olen) != 0) {
		if (ctx->st == ST_DONE) {
			mbedtls_aes_free(&ctx->aes);
			ctx->st = ST_CMD0;
		}
		k_mutex_unlock(&sec1_crypto_mu);
		return -EINVAL;
	}
	k_mutex_unlock(&sec1_crypto_mu);
	return 0;
}

bool esp_prov_sec1_is_ready(const esp_prov_sec1_t *ctx)
{
	bool ready;

	if (ctx == NULL) {
		return false;
	}
	k_mutex_lock(&sec1_crypto_mu, K_FOREVER);
	ready = ctx->st == ST_DONE;
	k_mutex_unlock(&sec1_crypto_mu);
	return ready;
}

int esp_prov_sec1_apply(esp_prov_sec1_t *ctx, uint8_t *data, size_t len)
{
	int ret;

	if (ctx == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&sec1_crypto_mu, K_FOREVER);
	if (ctx->st != ST_DONE) {
		k_mutex_unlock(&sec1_crypto_mu);
		return -EINVAL;
	}

	ret = mbedtls_aes_crypt_ctr(&ctx->aes, len, &ctx->nc_off, ctx->rand, ctx->stb, data, data);
	k_mutex_unlock(&sec1_crypto_mu);

	return ret == 0 ? 0 : -EIO;
}
