/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "esp_prov_internal.h"
#include "esp_prov_pb.h"

#include <inttypes.h>
#include <string.h>

#include <zephyr/autoconf.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/wifi.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/util.h>

LOG_MODULE_DECLARE(esp_prov_softap);

static struct k_mutex cred_mu;
static struct k_mutex finish_mu;
static struct k_sem done_sem;
static atomic_t stop_flag;
static atomic_t s_scan_prewarmed;
static bool finished_once;

static struct esp_wifi_credentials *out_dest;
static char sh_ssid[33];
static char sh_psk[65];
static bool sh_have_cred;
static bool sh_apply;

void esp_prov_shared_setup(struct esp_wifi_credentials *out)
{
	static bool inited;

	if (!inited) {
		k_mutex_init(&cred_mu);
		k_mutex_init(&finish_mu);
		k_sem_init(&done_sem, 0, 1);
		inited = true;
	}

	out_dest = out;
	finished_once = false;
	atomic_clear(&stop_flag);
	k_sem_reset(&done_sem);
}

void esp_prov_shared_reset(void)
{
	k_mutex_lock(&finish_mu, K_FOREVER);
	finished_once = false;
	k_mutex_unlock(&finish_mu);

	k_mutex_lock(&cred_mu, K_FOREVER);
	sh_ssid[0] = '\0';
	sh_psk[0] = '\0';
	sh_have_cred = false;
	sh_apply = false;
	k_mutex_unlock(&cred_mu);

	atomic_set(&s_scan_prewarmed, 0);
}

void esp_prov_shared_stop_request(void)
{
	atomic_set(&stop_flag, 1);
}

bool esp_prov_shared_stop_requested(void)
{
	return atomic_get(&stop_flag) != 0;
}

bool esp_prov_shared_wait_done(k_timeout_t timeout)
{
	return k_sem_take(&done_sem, timeout) == 0;
}

bool esp_prov_shared_is_finished(void)
{
	bool v;

	k_mutex_lock(&finish_mu, K_FOREVER);
	v = finished_once;
	k_mutex_unlock(&finish_mu);
	return v;
}

static void signal_finished(void)
{
	k_mutex_lock(&finish_mu, K_FOREVER);
	if (finished_once) {
		k_mutex_unlock(&finish_mu);
		return;
	}
	finished_once = true;
	k_mutex_unlock(&finish_mu);

	if (out_dest == NULL) {
		k_sem_give(&done_sem);
		return;
	}
	k_mutex_lock(&cred_mu, K_FOREVER);
	strncpy(out_dest->ssid, sh_ssid, sizeof(out_dest->ssid) - 1U);
	out_dest->ssid[sizeof(out_dest->ssid) - 1U] = '\0';
	strncpy(out_dest->psk, sh_psk, sizeof(out_dest->psk) - 1U);
	out_dest->psk[sizeof(out_dest->psk) - 1U] = '\0';
	k_mutex_unlock(&cred_mu);
	k_sem_give(&done_sem);
}

void esp_prov_shared_signal_finished(void)
{
	signal_finished();
}

int esp_prov_shared_dispatch_config(esp_prov_sec1_t *sec1, uint8_t *work, size_t wlen, uint8_t *resp,
				    size_t rcap, size_t *rlen, bool *finished_out)
{
	uint32_t mt = 0U;
	const uint8_t *ssid = NULL;
	size_t ssidl = 0U;
	const uint8_t *pass = NULL;
	size_t passl = 0U;

	*finished_out = false;

	if (esp_prov_pb_parse_wifi_config(work, wlen, &mt, &ssid, &ssidl, &pass, &passl) != 0) {
		return -1;
	}

	switch (mt) {
	case 2U: /* CmdSetConfig */
		if (ssid == NULL || ssidl == 0U || ssidl > 32U) {
			return -1;
		}
		k_mutex_lock(&cred_mu, K_FOREVER);
		memcpy(sh_ssid, ssid, ssidl);
		sh_ssid[ssidl] = '\0';
		if (pass != NULL && passl > 0U) {
			if (passl > 64U) {
				k_mutex_unlock(&cred_mu);
				return -1;
			}
			memcpy(sh_psk, pass, passl);
			sh_psk[passl] = '\0';
		} else {
			sh_psk[0] = '\0';
		}
		sh_have_cred = true;
		k_mutex_unlock(&cred_mu);
		return esp_prov_pb_build_wifi_resp_set_config(resp, rcap, rlen);
	case 4U: /* CmdApplyConfig */
		k_mutex_lock(&cred_mu, K_FOREVER);
		sh_apply = true;
		k_mutex_unlock(&cred_mu);
		return esp_prov_pb_build_wifi_resp_apply_config(resp, rcap, rlen);
	case 0U: /* CmdGetStatus */ {
		bool done;
		char ssid_copy[33];

		k_mutex_lock(&cred_mu, K_FOREVER);
		done = sh_apply && sh_have_cred;
		if (done) {
			memcpy(ssid_copy, sh_ssid, sizeof(ssid_copy));
			ssid_copy[32] = '\0';
		}
		k_mutex_unlock(&cred_mu);
		if (done) {
			int e = esp_prov_pb_build_wifi_resp_get_status_connected(
				resp, rcap, rlen, (const uint8_t *)ssid_copy, strlen(ssid_copy));

			if (e == 0) {
				*finished_out = true;
				/* Do not call signal_finished() here: SoftAP HTTP must send the encrypted
				 * body first -- prov_http_dns_abort() treats is_finished as abort and
				 * send_all() would drop the response (app sees failure; device still OK).
				 * Transports call esp_prov_shared_signal_finished() after TX. */
			}
			return e;
		}
		return esp_prov_pb_build_wifi_resp_get_status_connecting(resp, rcap, rlen);
	}
	default:
		return -1;
	}
}

/* -------- WiFi scan cache -------- */

#define SCAN_MAX_APS      20U
#define SCAN_TIMEOUT_SECS 25

static struct esp_prov_scan_ap scan_cache[SCAN_MAX_APS];
static atomic_t scan_ap_count;
static atomic_t scan_finished;

static struct net_mgmt_event_callback s_scan_cb;
static bool s_scan_cb_ok;

/* Rescans if a pass returns 0 AP(s) (coexistence / channel sweep still settling). */
#define SCAN_START_DEFER_MS   900U
#define SCAN_EMPTY_RETRY_MS   800U

static atomic_t s_scan_empty_rescan_budget;
static atomic_t s_scan_retry_after_empty;

/*
 * Dedicated workqueue for WiFi scan with a large stack.
 *
 * net_mgmt(NET_REQUEST_WIFI_SCAN) calls deep into the ESP32 WiFi driver
 * (esp_wifi_scan_start -> HAL shims -> event queue ops).  The system
 * workqueue default stack (1024 bytes) is too small and overflows silently,
 * corrupting the kernel's thread control block.  The corruption surfaces
 * later in z_swap (EXCCAUSE 28, VADDR=0x74) when the work item returns and
 * the workqueue tries to suspend the thread.
 *
 * Using a dedicated 4 kB workqueue keeps the system workqueue untouched and
 * gives the WiFi driver enough stack headroom.
 */
#define SCAN_WQ_STACK_SIZE 8192
#define SCAN_WQ_PRIORITY   K_PRIO_PREEMPT(5)

static K_THREAD_STACK_DEFINE(s_scan_wq_stack, SCAN_WQ_STACK_SIZE);
static struct k_work_q          s_scan_wq;
static struct k_work_delayable  s_scan_dwork;
static struct k_work_delayable s_scan_timeout_work;

static uint8_t zephyr_sec_to_auth(enum wifi_security_type sec)
{
	switch (sec) {
	case WIFI_SECURITY_TYPE_NONE:
		return 0U; /* Open */
	case WIFI_SECURITY_TYPE_WEP:
		return 1U; /* WEP */
	case WIFI_SECURITY_TYPE_PSK:
	case WIFI_SECURITY_TYPE_PSK_SHA256:
		return 3U; /* WPA2_PSK */
	case WIFI_SECURITY_TYPE_SAE:
		return 6U; /* WPA3_PSK */
	case WIFI_SECURITY_TYPE_SAE_AUTO:
		return 4U; /* WPA_WPA2_PSK */
	default:
		return 3U; /* default WPA2 */
	}
}

static void scan_event_cb(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
			  struct net_if *iface)
{
	ARG_UNUSED(iface);

	if (mgmt_event == NET_EVENT_WIFI_SCAN_RESULT) {
		const struct wifi_scan_result *res = (const struct wifi_scan_result *)cb->info;
		atomic_val_t idx = atomic_get(&scan_ap_count);

		if (res != NULL && idx < (atomic_val_t)SCAN_MAX_APS) {
			struct esp_prov_scan_ap *ap = &scan_cache[idx];
			uint8_t sl = (uint8_t)MIN(res->ssid_length, 32U);

			memcpy(ap->ssid, res->ssid, sl);
			ap->ssid[sl] = '\0';
			ap->ssid_len = sl;
			ap->channel  = res->channel;
			ap->rssi     = res->rssi;
			memcpy(ap->bssid, res->mac, 6U);
			ap->auth = zephyr_sec_to_auth(res->security);
			atomic_inc(&scan_ap_count);
		}
	} else if (mgmt_event == NET_EVENT_WIFI_SCAN_DONE) {
		(void)k_work_cancel_delayable(&s_scan_timeout_work);
		LOG_INF("WiFi scan done: %d AP(s)", (int)atomic_get(&scan_ap_count));

		if (atomic_get(&scan_ap_count) == 0 && atomic_get(&s_scan_empty_rescan_budget) != 0) {
			(void)atomic_dec(&s_scan_empty_rescan_budget);
			LOG_WRN("WiFi scan: 0 AP(s); retrying active scan after %" PRIu32 " ms (budget left %d)",
				(uint32_t)SCAN_EMPTY_RETRY_MS, (int)atomic_get(&s_scan_empty_rescan_budget));
			atomic_set(&s_scan_retry_after_empty, 1);
			atomic_set(&scan_finished, 0);
			k_work_reschedule_for_queue(&s_scan_wq, &s_scan_timeout_work,
						    K_SECONDS(SCAN_TIMEOUT_SECS));
			k_work_schedule_for_queue(&s_scan_wq, &s_scan_dwork, K_MSEC(SCAN_EMPTY_RETRY_MS));
			return;
		}

		atomic_set(&scan_finished, 1);
	}
}

static void scan_timeout_fn(struct k_work *work)
{
	ARG_UNUSED(work);
	if (atomic_get(&scan_finished) == 0) {
		LOG_WRN("WiFi scan timeout -- using %d AP(s) found so far",
			(int)atomic_get(&scan_ap_count));
		atomic_set(&scan_finished, 1);
	}
}

static void scan_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);

	if (atomic_get(&s_scan_retry_after_empty) != 0) {
		atomic_set(&s_scan_retry_after_empty, 0);
		atomic_set(&scan_ap_count, 0);
		memset(scan_cache, 0, sizeof(scan_cache));
	}

	if (!s_scan_cb_ok) {
		net_mgmt_init_event_callback(&s_scan_cb, scan_event_cb,
					     NET_EVENT_WIFI_SCAN_RESULT |
					     NET_EVENT_WIFI_SCAN_DONE);
		net_mgmt_add_event_callback(&s_scan_cb);
		s_scan_cb_ok = true;
	}

	/*
	 * Always use the SoftAP (SAP) net_if for NET_REQUEST_WIFI_SCAN, never STA.
	 *
	 * The Espressif Zephyr driver's WIFI_EVENT_SCAN_DONE path clears
	 * esp32_data.scan_cb on DT instance 0 (SAP). Issuing scan on the STA net_if
	 * leaves the callback on the wrong instance -> scan_done can call NULL ->
	 * EXCCAUSE 20 / PC 0 in the wifi thread (seen with "WiFi scan: STA iface").
	 *
	 * When BLE is the chosen transport we no longer call wifi_ap_stop() mid-session
	 * (see softap_shutdown_work_fn): SAP stays in a consistent state for scan;
	 * the AP is disabled only at session end in esp_prov_routine_run().
	 */
	struct net_if *scan_if = net_if_get_wifi_sap();

	if (scan_if == NULL) {
		LOG_WRN("scan: no SAP Wi-Fi interface -- empty list");
		atomic_set(&scan_finished, 1);
		return;
	}

	/* Active scan: probe requests populate the list reliably. Passive scan
	 * often returned 0 AP(s) here under SoftAP + BLE + immediate LOG (driver
	 * "Failed to send packet" during passive channel hops). Slightly more
	 * airtime than passive; dwell hints may be ignored by esp32_wifi_scan(). */
	struct wifi_scan_params params = {
		.scan_type         = WIFI_SCAN_TYPE_ACTIVE,
		.dwell_time_active = 120U,
		.dwell_time_passive = 120U,
		.max_bss_cnt       = SCAN_MAX_APS,
	};

	int err = net_mgmt(NET_REQUEST_WIFI_SCAN, scan_if, &params, sizeof(params));

	if (err != 0) {
		LOG_WRN("WiFi scan request failed (%d) -- empty list", err);
		atomic_set(&scan_finished, 1);
	} else {
		LOG_DBG("WiFi active scan started on SAP net_if (required for esp32 scan_cb)");
		k_work_reschedule_for_queue(&s_scan_wq, &s_scan_timeout_work,
					    K_SECONDS(SCAN_TIMEOUT_SECS));
	}
}

static void scan_wq_ensure_started(void)
{
	static bool wq_started;

	if (!wq_started) {
		k_work_queue_init(&s_scan_wq);
		k_work_queue_start(&s_scan_wq, s_scan_wq_stack,
				   K_THREAD_STACK_SIZEOF(s_scan_wq_stack),
				   SCAN_WQ_PRIORITY, NULL);
		k_work_init_delayable(&s_scan_dwork, scan_work_fn);
		k_work_init_delayable(&s_scan_timeout_work, scan_timeout_fn);
		wq_started = true;
	}
}

static void scan_start(void)
{
	scan_wq_ensure_started();

	(void)k_work_cancel_delayable(&s_scan_dwork);
	(void)k_work_cancel_delayable(&s_scan_timeout_work);

	atomic_set(&scan_ap_count, 0);
	atomic_set(&scan_finished, 0);
	atomic_set(&s_scan_empty_rescan_budget, 2);
	atomic_set(&s_scan_retry_after_empty, 0);
	memset(scan_cache, 0, sizeof(scan_cache));

	/* Defer scan: after HTTP/BLE traffic the driver often logs esp_wifi_internal_tx failures
	 * if scan starts too soon under APSTA + coexistence. */
	k_work_schedule_for_queue(&s_scan_wq, &s_scan_dwork, K_MSEC(SCAN_START_DEFER_MS));
	LOG_INF("WiFi scan queued (starts in %" PRIu32 " ms)", (uint32_t)SCAN_START_DEFER_MS);
}

#define PRESCAN_POLL_MS    50U
#define PRESCAN_WAIT_SECS  32

void esp_prov_shared_prescan_after_ap(void)
{
	int64_t deadline = k_uptime_get() + (int64_t)PRESCAN_WAIT_SECS * 1000;

	scan_wq_ensure_started();
	(void)k_work_cancel_delayable(&s_scan_dwork);
	(void)k_work_cancel_delayable(&s_scan_timeout_work);

	atomic_set(&scan_ap_count, 0);
	atomic_set(&scan_finished, 0);
	atomic_set(&s_scan_empty_rescan_budget, 2);
	atomic_set(&s_scan_retry_after_empty, 0);
	memset(scan_cache, 0, sizeof(scan_cache));

	k_work_schedule_for_queue(&s_scan_wq, &s_scan_dwork, K_MSEC(SCAN_START_DEFER_MS));
	LOG_DBG("WiFi prescan after AP up (cache results before BLE): first pass in %" PRIu32 " ms",
		(uint32_t)SCAN_START_DEFER_MS);

	while (atomic_get(&scan_finished) == 0) {
		if (k_uptime_get() > deadline) {
			LOG_WRN("WiFi prescan timed out -- on-demand scan on CmdScanStart");
			(void)k_work_cancel_delayable(&s_scan_dwork);
			(void)k_work_cancel_delayable(&s_scan_timeout_work);
			atomic_set(&scan_ap_count, 0);
			atomic_set(&scan_finished, 1);
			return;
		}
		k_sleep(K_MSEC(PRESCAN_POLL_MS));
	}

	atomic_set(&s_scan_prewarmed, 1);
	LOG_DBG("WiFi prescan done: %d AP(s) in cache (BLE serves CmdScanResult from cache)",
		(int)atomic_get(&scan_ap_count));
}

int esp_prov_shared_dispatch_scan(esp_prov_sec1_t *sec1, uint8_t *work, size_t wlen, uint8_t *resp,
				  size_t rcap, size_t *rlen)
{
	uint32_t mt = 0U;

	ARG_UNUSED(sec1);
	if (esp_prov_pb_parse_scan_msg_type(work, wlen, &mt) != 0) {
		return -1;
	}

	switch (mt) {
	case 0U: /* CmdScanStart */
		if (atomic_get(&s_scan_prewarmed) != 0) {
			LOG_DBG("CmdScanStart: using pre-warmed scan cache (%d APs), no new scan",
				(int)atomic_get(&scan_ap_count));
		} else {
			scan_start();
		}
		return esp_prov_pb_build_scan_resp_start(resp, rcap, rlen);

	case 2U: /* CmdScanStatus */
		return esp_prov_pb_build_scan_resp_status(
			resp, rcap, rlen,
			(uint32_t)atomic_get(&scan_ap_count),
			atomic_get(&scan_finished) != 0);

	case 4U: /* CmdScanResult */ {
		uint32_t start = 0U, count = 4U;

		esp_prov_pb_parse_cmd_scan_result(work, wlen, &start, &count);
		return esp_prov_pb_build_scan_resp_result(
			resp, rcap, rlen,
			scan_cache, (uint32_t)atomic_get(&scan_ap_count),
			start, count);
	}

	default:
		return -1;
	}
}
