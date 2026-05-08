/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Packet sniffing / trace helpers: esp_prov_trace_app() and esp_prov_trace_note().
 * All traffic emits under the "esp_prov_pkt" LOG module so enabling CONFIG_ESP_PROV_APP_TRACE
 * or CONFIG_ESP_PROV_PKT_LOG yields a clean, dedicated stream without mixing with
 * the normal provisioning lifecycle (esp_prov_softap, esp_prov_ble, esp_prov_session).
 *
 * Packet detail is only visible when this module's LOG level is DBG and the
 * features are enabled; at INFO level the LOG_DBG calls compile out.
 */

#include "esp_prov_internal.h"

#include <stddef.h>
#include <string.h>

#include <zephyr/autoconf.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/util.h>

LOG_MODULE_REGISTER(esp_prov_pkt, CONFIG_ESP_PROV_LOG_LEVEL);

#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE) || IS_ENABLED(CONFIG_ESP_PROV_PKT_LOG) ||                \
	IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)

static uint32_t prov_next_pkt_id(void)
{
	static atomic_t seq;

	return (uint32_t)atomic_inc(&seq) + 1U;
}

void esp_prov_trace_note(const char *msg)
{
	LOG_DBG("%s", msg);
}

void esp_prov_trace_app(const char *where, const char *dir, const void *data, size_t len)
{
	uint32_t id = prov_next_pkt_id();

	LOG_DBG("prov pkt #%u %s %s len=%zu", id, where, dir, len);

#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE)
	{
		const uint8_t *b = data;
		size_t maxd = (size_t)CONFIG_ESP_PROV_APP_TRACE_MAX_BYTES;

		if (data == NULL || len == 0U) {
			return;
		}
		if (len > maxd) {
			LOG_DBG("(hex truncating to %zu bytes)", maxd);
			len = maxd;
		}
		for (size_t off = 0U; off < len; off += 24U) {
			char hx[24U * 2U + 1U];
			size_t chunk = MIN(len - off, 24U);

			(void)bin2hex(b + off, chunk, hx, sizeof(hx));
			LOG_DBG("  %04zu %s", off, hx);
		}
	}
#endif
}
#endif
