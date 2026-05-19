/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Zephyr-only implementation internals (SoftAP + BLE + sec1). Not a public API;
 * applications include only esp_prov.h.
 */

#ifndef ESP_PROV_INTERNAL_H
#define ESP_PROV_INTERNAL_H

#include "esp_prov.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/autoconf.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

BUILD_ASSERT(IS_ENABLED(CONFIG_ESP_PROV_USE_BLE) || IS_ENABLED(CONFIG_ESP_PROV_USE_SOFTAP),
	     "At least one provisioning transport must be enabled "
	     "(CONFIG_ESP_PROV_USE_BLE and/or CONFIG_ESP_PROV_USE_SOFTAP)");

/*
 * Core provisioning/session INF lines (started / done / cancel / timeout) always compile;
 * they no longer depend on ESP_PROV_DIAG_LEVEL. Diagnostics choice still gates trace/PDU extras.
 */
#define ESP_PROV_USER_MILESTONES 1

#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE) || IS_ENABLED(CONFIG_ESP_PROV_PKT_LOG) ||                \
	IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)
void esp_prov_trace_app(const char *where, const char *dir, const void *data, size_t len);
void esp_prov_trace_note(const char *msg);
#else
static inline void esp_prov_trace_app(const char *where, const char *dir, const void *data,
					size_t len)
{
	ARG_UNUSED(where);
	ARG_UNUSED(dir);
	ARG_UNUSED(data);
	ARG_UNUSED(len);
}

static inline void esp_prov_trace_note(const char *msg)
{
	ARG_UNUSED(msg);
}
#endif

/* --- Protocomm security1 (mbedTLS); used by HTTP and BLE transports --- */

typedef struct esp_prov_sec1 esp_prov_sec1_t;

esp_prov_sec1_t *esp_prov_sec1_http(void);
esp_prov_sec1_t *esp_prov_sec1_ble(void);

/**
 * Seed the sec1 CTR-DRBG up front, in a calm RF window, so the first protocomm
 * transport_open() does not race the BLE central connect against SoftAP traffic
 * (mbedtls_entropy_func -52 / MBEDTLS_ERR_ENTROPY_SOURCE_FAILED). Idempotent:
 * subsequent calls return immediately when the DRBG is already seeded. Returns
 * 0 on success or -EIO if entropy is still starved after the internal retry
 * budget -- caller may continue and let transport_open() retry under the BT RX
 * thread (existing fallback path).
 */
int esp_prov_sec1_rng_prewarm(void);

void esp_prov_sec1_reset(esp_prov_sec1_t *ctx);

int esp_prov_sec1_transport_open(esp_prov_sec1_t *ctx, uint32_t session_id);
int esp_prov_sec1_transport_close(esp_prov_sec1_t *ctx, uint32_t session_id);

int esp_prov_sec1_process_session(esp_prov_sec1_t *ctx, const uint8_t *req, size_t req_len,
				  const char *pop, uint8_t *resp, size_t resp_cap, size_t *resp_len);

bool esp_prov_sec1_is_ready(const esp_prov_sec1_t *ctx);

int esp_prov_sec1_apply(esp_prov_sec1_t *ctx, uint8_t *data, size_t len);

/* Match Espressif wifi_provisioning JSON (see manager.c) + Rust PROTO_VER_JSON. */
#define ESP_PROV_JSON_PROTO_VER                                                                    \
	"{\"prov\":{\"ver\":\"v1.1\",\"sec_ver\":1,\"sec_patch_ver\":0,\"cap\":[\"wifi_scan\"]}}"

void esp_prov_shared_setup(struct esp_wifi_credentials *out_dest);
void esp_prov_shared_reset(void);

/** Module-internal cancel (wall-clock timeout, BLE idle disconnect). */
void esp_prov_cancel_system(void);

/**
 * After SoftAP is enabled (first esp_wifi_start from this app), run one Wi-Fi scan and fill
 * the scan cache -- same role as Rust `wifi_ap::scan_wifi_for_prov` before HTTP/BLE, so BLE
 * `CmdScanStatus` / `CmdScanResult` read cached APs without scanning during the GATT session.
 */
void esp_prov_shared_prescan_after_ap(void);

void esp_prov_shared_stop_request(void);
bool esp_prov_shared_stop_requested(void);

/** Block until a transport reports success. */
bool esp_prov_shared_wait_done(k_timeout_t timeout);

bool esp_prov_shared_is_finished(void);

/** After successful GetStatus(connected) plaintext build -- call after encrypted response is on the wire. */
void esp_prov_shared_signal_finished(void);

/**
 * WiFi config handler (plaintext buffer). Sets @a finished when GetStatus returns connected.
 * @return 0 on success, -1 on error
 */
int esp_prov_shared_dispatch_config(esp_prov_sec1_t *sec1, uint8_t *work, size_t wlen, uint8_t *resp,
				     size_t rcap, size_t *rlen, bool *finished_out);

int esp_prov_shared_dispatch_scan(esp_prov_sec1_t *sec1, uint8_t *work, size_t wlen, uint8_t *resp,
				  size_t rcap, size_t *rlen);


/** Internal: bt_enable(), settings_load, ESP32 TX power; called from esp_prov_run() when BLE is on. */
int esp_prov_bt_enable(void);
int esp_prov_ble_start(void);
void esp_prov_ble_stop(void);

/** Transport arbitration: first BLE link or first real SoftAP prov request wins (not captive 204). */
#define ESP_PROV_TP_NONE    0
#define ESP_PROV_TP_BLE     1
#define ESP_PROV_TP_SOFTAP  2

bool esp_prov_try_select_ble(void);
void esp_prov_try_select_softap(void);
int esp_prov_transport_choice(void);

/**
 * Provisioning routine: SoftAP, HTTP, DNS, BLE, inner wait until success or stop.
 * No wall-clock session limit (enforced by prov_controller). Called from routine thread only.
 */
int esp_prov_routine_run(struct esp_wifi_credentials *out);

#endif /* ESP_PROV_INTERNAL_H */
