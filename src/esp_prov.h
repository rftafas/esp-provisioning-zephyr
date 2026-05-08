/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Public API: Wi-Fi provisioning compatible with the Espressif BLE Provisioning
 * app (protocomm over SoftAP HTTP and/or BLE GATT) on Zephyr / Espressif ESP32.
 *
 * Policy:
 *  - On success, returns credentials only; does not persist or reboot.
 *  - The caller must stop conflicting users of the radio (e.g. other BLE roles)
 *    before calling into this module, and decides persistence / reboot / STA.
 */

#ifndef ESP_PROV_H
#define ESP_PROV_H

#include <stddef.h>
#include <stdbool.h>

#include <zephyr/autoconf.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the Bluetooth controller/host once: bt_enable(), settings_load() for bonds,
 * and ESP32 BLE TX power. Idempotent. Call from application startup before BLE HID
 * advertising and/or esp_prov_run().
 */
int esp_prov_bt_enable(void);

/** Default PoP for sec1 (Espressif app). */
#define ESP_PROV_DEFAULT_POP CONFIG_ESP_PROV_POP

/** SoftAP SSID for provisioning mode (product spec). */
#define ESP_PROV_SOFTAP_SSID CONFIG_ESP_PROV_SOFTAP_SSID

enum esp_prov_result {
	ESP_PROV_OK = 0,
	ESP_PROV_ERR_CANCELLED,
	ESP_PROV_ERR_TIMEOUT,
	ESP_PROV_ERR_NO_MEM,
	ESP_PROV_ERR_INTERNAL,
	/** Build or transport not available. */
	ESP_PROV_ERR_NOT_IMPLEMENTED,
};

struct esp_wifi_credentials {
	char ssid[33];
	char psk[65];
};

/**
 * Run one provisioning session until success, cancel, or wall-clock timeout
 * (CONFIG_ESP_PROV_SESSION_TIMEOUT_SEC; BLE disconnects do not end the session).
 * Blocks the calling thread.
 *
 * Internally: the session wall-clock limit is enforced outside the SoftAP HTTP
 * worker (see references/provisioning.md): the caller runs a small join/deadline
 * loop while protocomm runs on a dedicated prov-routine thread.
 *
 * Session start/end lines use the Zephyr log module **esp_prov_session** (same as
 * prov_controller); level is CONFIG_ESP_PROV_LOG_LEVEL.
 *
 * On ESP_PROV_OK, fills out with NUL-terminated ssid and psk.
 */
int esp_prov_run(struct esp_wifi_credentials *out);

/**
 * Request cancellation of an in-progress esp_prov_run() from a normal thread (not ISR).
 * Sets the stop flag, preemptively shuts down SoftAP HTTP/DNS/TLS sockets so prov-http /
 * prov-dns wake, then queues BLE stop on the system workqueue. esp_prov_run() returns
 * ESP_PROV_ERR_CANCELLED after join/cleanup.
 */
void esp_prov_cancel(void);

/**
 * Same stop + teardown as esp_prov_cancel(), but ISR- and oops-safe: only sets the stop
 * flag and submits the work item (socket shutdown + BLE run on the system workqueue).
 * Do not call esp_prov_cancel() from ISR -- use this.
 */
void esp_prov_cancel_isr(void);

/**
 * True when user-initiated cancel (short press, GPIO IRQ) should call
 * esp_prov_cancel() / esp_prov_cancel_isr().
 *
 * Returns false until the provisioning routine has finished SoftAP/HTTP/DNS/BLE
 * bring-up ("session ready"); this blocks spurious cancel during that window.
 * After session ready: if CONFIG_ESP_PROV_USER_CANCEL_COOLDOWN_MS is 0, returns true;
 * if non-zero, returns false until that many milliseconds have elapsed after ready
 * (optional debounce). Wall-clock session timeout uses esp_prov_cancel() directly
 * and is not gated by this function.
 */
bool esp_prov_user_cancel_may_run(void);

#ifdef __cplusplus
}
#endif

#endif /* ESP_PROV_H */
