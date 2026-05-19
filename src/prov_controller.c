/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Runs esp_prov_routine_run() on a dedicated thread; caller thread polls join and
 * session deadline so HTTP/DNS stuck states are handled without relying on the
 * server thread to detect itself.
 */

#include "prov_controller.h"
#include "esp_prov_internal.h"

#include <string.h>

#include <zephyr/autoconf.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(esp_prov_session, CONFIG_ESP_PROV_LOG_LEVEL);

struct prov_routine_ctx {
	struct esp_wifi_credentials *out;
	int result;
};

static struct k_thread prov_routine_thread;
K_THREAD_STACK_DEFINE(prov_routine_stack, CONFIG_ESP_PROV_ROUTINE_STACK_SIZE);

static void prov_routine_thread_fn(void *p1, void *p2, void *p3)
{
	struct prov_routine_ctx *ctx = p1;

	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	ctx->result = esp_prov_routine_run(ctx->out);
}

static void prov_log_session_result(int err, const struct esp_wifi_credentials *out)
{
	switch (err) {
	case ESP_PROV_OK:
		LOG_INF("Provisioning done: ssid=\"%s\" (ssid_len=%u)", out->ssid,
			(unsigned int)strnlen(out->ssid, sizeof(out->ssid)));
		break;
	case ESP_PROV_ERR_NOT_IMPLEMENTED:
		LOG_WRN("Provisioning not available (build or transport)");
		break;
	case ESP_PROV_ERR_CANCELLED:
		LOG_WRN("Provisioning cancelled");
		break;
	case ESP_PROV_ERR_TIMEOUT:
		LOG_WRN("Provisioning timed out");
		break;
	default:
		LOG_ERR("Provisioning failed: %d", err);
		break;
	}
}

int prov_controller_run_blocking(struct esp_wifi_credentials *out)
{
	struct prov_routine_ctx ctx = {
		.out = out,
		.result = ESP_PROV_ERR_INTERNAL,
	};
	int64_t deadline = k_uptime_get() +
			   (int64_t)CONFIG_ESP_PROV_SESSION_TIMEOUT_SEC * 1000LL;
	bool wall_clock_expired = false;

	if (out == NULL) {
		return ESP_PROV_ERR_INTERNAL;
	}

	LOG_INF("Provisioning started");

	LOG_DBG("Provisioning controller: routine thread starting (session limit %u s)",
		(unsigned int)CONFIG_ESP_PROV_SESSION_TIMEOUT_SEC);

	k_thread_create(&prov_routine_thread, prov_routine_stack,
			K_THREAD_STACK_SIZEOF(prov_routine_stack), prov_routine_thread_fn, &ctx, NULL,
			NULL, K_PRIO_PREEMPT(10), 0, K_NO_WAIT);
	k_thread_name_set(&prov_routine_thread, "prov-routine");

	for (;;) {
		if (k_thread_join(&prov_routine_thread, K_NO_WAIT) == 0) {
			break;
		}

		if (k_uptime_get() >= deadline) {
			LOG_WRN("Provisioning controller: wall-clock limit reached, requesting cancel");
			wall_clock_expired = true;
			esp_prov_cancel_system();
			if (k_thread_join(&prov_routine_thread, K_SECONDS(30)) != 0) {
				LOG_ERR("Provisioning controller: routine thread did not exit after cancel");
				return ESP_PROV_ERR_INTERNAL;
			}
			break;
		}

		k_sleep(K_MSEC(200));
	}

	if (wall_clock_expired) {
		LOG_INF("Provisioning controller: session ended after wall-clock limit");
		prov_log_session_result(ESP_PROV_ERR_TIMEOUT, out);
		return ESP_PROV_ERR_TIMEOUT;
	}

	LOG_DBG("Provisioning controller: routine exited (result=%d)", ctx.result);
	prov_log_session_result(ctx.result, out);
	return ctx.result;
}
