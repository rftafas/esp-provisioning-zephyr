/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Espressif WiFi provisioning over BLE (protocomm GATT, same UUID layout as ESP-IDF scheme_ble).
 *
 * Protocol (matches ESP-IDF protocomm_ble with ble_notify=1 and the Rust TrouBLE port):
 *   - Each characteristic has NOTIFY property + CCCD + User Description (0x2901).
 *   - Phone subscribes (CCCD write 0x0001) then writes a request.
 *   - Device responds via ATT Notify on the same characteristic (NOT by storing for reads).
 *   - Reads on characteristics are supported too (fallback / read-only proto-ver).
 */

#include "esp_prov_internal.h"
#include "esp_prov.h"

#include <zephyr/autoconf.h>

#if IS_ENABLED(CONFIG_ESP_PROV_USE_BLE)

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/util.h>

#if IS_ENABLED(CONFIG_BT_ESP32)
#include <esp_bt.h>
#endif

LOG_MODULE_REGISTER(esp_prov_ble, CONFIG_ESP_PROV_LOG_LEVEL);


#if IS_ENABLED(CONFIG_BT_ESP32)
/* esp_power_level_t is a coarse table (-24..+21 dBm). Pick closest to CONFIG_ESP32_PHY_MAX_TX_POWER. */
static esp_power_level_t ble_pwr_level_from_dbm(int dbm)
{
	static const int8_t dbm_table[] = { -24, -21, -18, -15, -12, -9, -6, -3, 0, 3, 6, 9, 12, 15, 18, 21 };
	int best_i = 9; /* P9 (+9 dBm) */
	int best_d = 100;

	if (dbm < -24) {
		dbm = -24;
	} else if (dbm > 21) {
		dbm = 21;
	}
	for (size_t i = 0; i < ARRAY_SIZE(dbm_table); i++) {
		int d = dbm - dbm_table[i];

		if (d < 0) {
			d = -d;
		}
		if (d < best_d) {
			best_d = d;
			best_i = (int)i;
		}
	}
	return (esp_power_level_t)best_i;
}

static void esp_prov_ble_apply_tx_power(void)
{
	const int target_dbm = CONFIG_ESP32_PHY_MAX_TX_POWER;
	const esp_power_level_t lvl = ble_pwr_level_from_dbm(target_dbm);

	(void)esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_DEFAULT, lvl);
	(void)esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, lvl);
	(void)esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_SCAN, lvl);
	LOG_DBG("BLE TX power: target %d dBm (Kconfig) -> vendor level %d (~%d dBm)", target_dbm, (int)lvl,
		(int)(-24 + (int)lvl * 3));
}
#endif /* CONFIG_BT_ESP32 */

#define EP_SCAN   0U
#define EP_SESS   1U
#define EP_CFG    2U
#define EP_VER    3U

#define RSP_MAX 512U

/* Default Espressif provisioning service UUID (scheme_ble.c), little-endian val[] */
#define ESP_PROV_SVC_UUID \
	BT_UUID_DECLARE_128(0x07, 0xed, 0x9b, 0x2d, 0x0f, 0x06, 0x7c, 0x87, 0x9b, 0x43, 0x43, 0x6b, \
			    0x4d, 0x24, 0x75, 0x17)

#define ESP_CHAR_UUID(u16) \
	BT_UUID_DECLARE_128(0x07, 0xed, 0x9b, 0x2d, 0x0f, 0x06, 0x7c, 0x87, 0x9b, 0x43, 0x43, 0x6b, \
			    ((u16) & 0xff), (((u16) >> 8) & 0xff), 0x75, 0x17)

/*
 * BLE GATT response buffers (4 x 512 B = ~2 KiB in `.bss`). The earlier heap-backed
 * struct prov_ble_ctx (k_malloc in esp_prov_ble_start, k_free in esp_prov_ble_stop) was
 * reverted in 2026-04-29: the ~2 KiB heap demand competed with the Wi-Fi adapter's
 * wifi_malloc() under SoftAP+BLE peaks (see references/journal.md, "SoftAP regression").
 *
 * `s_prov_gatt_work` is the GATT decrypt scratch -- it must not live on the BT RX thread
 * stack (sec1 Curve25519 + mbedTLS is deep; see PoP / BT RX WQ entries in the journal).
 */
static uint8_t rsp_scan[RSP_MAX];
static uint16_t rsp_scan_len;
static uint8_t rsp_sess[RSP_MAX];
static uint16_t rsp_sess_len;
static uint8_t rsp_cfg[RSP_MAX];
static uint16_t rsp_cfg_len;
static uint8_t s_prov_gatt_work[RSP_MAX];

static struct bt_conn *ble_conn;
static uint32_t ble_sess_id;
static atomic_t ble_adv_on;
static atomic_t prov_gatt_registered;
/** Set after a successful BLE central connection this session (enables idle-after-disc cancel). */
static bool ble_had_central_link;

/*
 * Final prov-config response may be RSP-BUFFERED (notify failed / no CCCD): the phone
 * reads FF52. esp_prov_shared_signal_finished() must run only after that data is delivered,
 * else wait_done returns, esp_prov_ble_stop() disconnects (HCI 0x16) before the Read.
 */
static bool ble_cfg_finish_signal_after_read;

static uint8_t *rsp_buf_for_ep(uintptr_t ep)
{
	switch (ep) {
	case EP_SCAN:
		return rsp_scan;
	case EP_SESS:
		return rsp_sess;
	case EP_CFG:
		return rsp_cfg;
	default:
		return NULL;
	}
}

static uint16_t *rsp_len_for_ep(uintptr_t ep)
{
	switch (ep) {
	case EP_SCAN:
		return &rsp_scan_len;
	case EP_SESS:
		return &rsp_sess_len;
	case EP_CFG:
		return &rsp_cfg_len;
	default:
		return NULL;
	}
}

#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE) || IS_ENABLED(CONFIG_ESP_PROV_PKT_LOG) ||                \
	IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)
static const char *ep_tag(uintptr_t ep)
{
	switch (ep) {
	case EP_SCAN:
		return "ble/ff50-scan";
	case EP_SESS:
		return "ble/ff51-sess";
	case EP_CFG:
		return "ble/ff52-cfg";
	case EP_VER:
		return "ble/ff53-ver";
	default:
		return "ble/?";
	}
}
#endif

/* ---------- GATT helpers ---------- */

static void prov_ccc_cfg_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	ARG_UNUSED(attr);
#if IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)
	LOG_DBG("[prov-c] CCCD value=0x%04x", value);
#endif
}

static ssize_t read_user_desc(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			      void *buf, uint16_t len, uint16_t offset)
{
	const char *s = (const char *)attr->user_data;

	return bt_gatt_attr_read(conn, attr, buf, len, offset, s, strlen(s));
}

/* ---------- Characteristic read (fallback; primary path is write+notify) ---------- */

static ssize_t prov_read_ep(struct bt_conn *conn, const struct bt_gatt_attr *attr, void *buf,
			    uint16_t len, uint16_t offset)
{
	uintptr_t ep = (uintptr_t)attr->user_data;
	ssize_t ret;

	if (ep == EP_VER) {
		ret = bt_gatt_attr_read(conn, attr, buf, len, offset, ESP_PROV_JSON_PROTO_VER,
					sizeof(ESP_PROV_JSON_PROTO_VER) - 1U);
	} else {
		uint16_t *ll = rsp_len_for_ep(ep);
		uint8_t *rb = rsp_buf_for_ep(ep);

		if (rb == NULL || ll == NULL) {
			return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
		}
		ret = bt_gatt_attr_read(conn, attr, buf, len, offset, rb, *ll);
		if (ep == EP_CFG && ble_cfg_finish_signal_after_read && ret > 0 &&
		    (size_t)offset + (size_t)ret >= (size_t)*ll) {
			ble_cfg_finish_signal_after_read = false;
			esp_prov_shared_signal_finished();
		}
	}

#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE) || IS_ENABLED(CONFIG_ESP_PROV_PKT_LOG) ||                \
	IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)
	if (ret > 0) {
		esp_prov_trace_app(ep_tag(ep), "READ-TX", buf, (size_t)ret);
	} else {
		LOG_DBG("BLE read %s offset=%u ret=%zd (no payload)", ep_tag(ep), offset, (ssize_t)ret);
#if IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)
		LOG_DBG("[prov-c] BLE-READ %s off=%u req_max=%u ret=%zd", ep_tag(ep), offset, len, ret);
#endif
	}
#endif
	return ret;
}

/* ---------- Characteristic write -> process -> notify response ---------- */

static ssize_t prov_write_ep(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			     const void *buf, uint16_t len, uint16_t offset, uint8_t flags)
{
	uintptr_t ep = (uintptr_t)attr->user_data;
	esp_prov_sec1_t *sec1 = esp_prov_sec1_ble();
	uint16_t *outl = rsp_len_for_ep(ep);
	uint8_t *rsp = rsp_buf_for_ep(ep);
	uint8_t *work = s_prov_gatt_work;
	bool finished = false;
	size_t ol = 0U;
	int err;

	if (ep == EP_VER) {
#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE) || IS_ENABLED(CONFIG_ESP_PROV_PKT_LOG) ||                \
	IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)
		if (len > 0U) {
			esp_prov_trace_app(ep_tag(EP_VER), "RX", buf, len);
		}
#endif
		/* Respond with proto-ver JSON via notify (same as ESP-IDF ble_notify=1).
		 * proto-ver does NOT count as protocomm engagement (mirrors SoftAP, where
		 * http_req_is_provisioning() drives selection only for real prov-* paths).
		 */
		(void)bt_gatt_notify(conn, attr, ESP_PROV_JSON_PROTO_VER,
				     sizeof(ESP_PROV_JSON_PROTO_VER) - 1U);
		return (ssize_t)len;
	}

	if (rsp == NULL || outl == NULL) {
		return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
	}

	/*
	 * First protocomm WRITE on EP_SCAN/EP_SESS/EP_CFG selects BLE as the session
	 * transport. If SoftAP already won, reject this write and tear down the link
	 * (same outcome as the previous connect-time rejection).
	 */
	if ((flags & BT_GATT_WRITE_FLAG_PREPARE) == 0U && !esp_prov_try_select_ble()) {
		LOG_WRN("BLE: rejected -- SoftAP provisioning already selected");
		(void)bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
		return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
	}

	if (flags & BT_GATT_WRITE_FLAG_PREPARE) {
		if ((size_t)offset + len > RSP_MAX) {
#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE) || IS_ENABLED(CONFIG_ESP_PROV_PKT_LOG) ||                \
	IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)
			esp_prov_trace_note("BLE: prepare exceeds RSP_MAX (reject)");
#endif
			return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
		}
#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE) || IS_ENABLED(CONFIG_ESP_PROV_PKT_LOG) ||                \
	IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)
		char wdesc[72];

		snprintf(wdesc, sizeof(wdesc), "%s prepare off=%u", ep_tag(ep), offset);
		esp_prov_trace_app(wdesc, "RX", buf, len);
#endif
		/* Zephyr prep_write_cb() requires exactly 0 (not len); else ATT error. */
		return 0;
	}

	if (len == 0U || len > RSP_MAX || offset != 0U) {
#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE) || IS_ENABLED(CONFIG_ESP_PROV_PKT_LOG) ||                \
	IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)
		LOG_WRN("BLE write %s: reject len=%u offset=%u (expect offset 0 for execute)",
			ep_tag(ep), len, offset);
#endif
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}
	memcpy(work, buf, len);

#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE) || IS_ENABLED(CONFIG_ESP_PROV_PKT_LOG) ||                \
	IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)
	esp_prov_trace_app(ep_tag(ep), "RX", work, len);
#endif

	switch (ep) {
	case EP_SESS:
		err = esp_prov_sec1_process_session(sec1, work, len, ESP_PROV_DEFAULT_POP, rsp, RSP_MAX,
						    &ol);
		break;
	case EP_CFG:
		if (!esp_prov_sec1_is_ready(sec1)) {
			return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
		}
		if (esp_prov_sec1_apply(sec1, work, len) != 0) {
			return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
		}
		ol = 0U;
		err = esp_prov_shared_dispatch_config(sec1, work, len, rsp, RSP_MAX, &ol, &finished);
		if (err == 0 && esp_prov_sec1_apply(sec1, rsp, ol) != 0) {
			err = -1;
		}
		break;
	case EP_SCAN:
		if (!esp_prov_sec1_is_ready(sec1)) {
			return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
		}
		if (esp_prov_sec1_apply(sec1, work, len) != 0) {
			return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
		}
		ol = 0U;
		err = esp_prov_shared_dispatch_scan(sec1, work, len, rsp, RSP_MAX, &ol);
		if (err == 0 && esp_prov_sec1_apply(sec1, rsp, ol) != 0) {
			err = -1;
		}
		break;
	default:
		return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
	}

	if (err != 0) {
#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE) || IS_ENABLED(CONFIG_ESP_PROV_PKT_LOG) ||                \
	IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)
		esp_prov_trace_note("BLE: endpoint handler error (BT_ATT_ERR_VALUE_NOT_ALLOWED)");
#endif
		return BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
	}
	if (ol > RSP_MAX) {
		return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
	}
	*outl = (uint16_t)ol;

	/* Attempt notify; if the phone hasn't subscribed (CCCD = 0x0000), this
	 * returns -EINVAL silently.  The phone will fall back to a plain ATT
	 * Read request on the same characteristic, which prov_read_ep() serves
	 * from the rsp_xxx buffer we just filled. */
	if (ol > 0U) {
		int nret = bt_gatt_notify(conn, attr, rsp, (uint16_t)ol);

#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE) || IS_ENABLED(CONFIG_ESP_PROV_PKT_LOG) ||                \
	IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)
		if (nret == 0) {
			esp_prov_trace_app(ep_tag(ep), "NOTIFY-TX", rsp, ol);
		} else {
			/* Phone will read instead -- trace the pending response. */
			esp_prov_trace_app(ep_tag(ep), "RSP-BUFFERED(expect-READ)", rsp, ol);
		}
#else
		(void)nret;
#endif
		if (finished) {
			if (nret == 0) {
				esp_prov_shared_signal_finished();
			} else {
				ble_cfg_finish_signal_after_read = true;
			}
		}
	} else if (finished) {
		esp_prov_shared_signal_finished();
	}
	return (ssize_t)len;
}

/*
 * GATT service: Read+Write+Notify on every characteristic, each followed by
 * a CCCD (for notification subscription) and a User Description (0x2901) so
 * the Espressif Provisioning app can discover endpoint names.
 *
 * Attribute layout (esp_prov_svc.attrs[]):
 *  [0]  service declaration
 *  [1,2]  prov-scan decl + value   [3] scan CCCD  [4] scan user-desc
 *  [5,6]  prov-session decl + val  [7] sess CCCD  [8] sess user-desc
 *  [9,10] prov-config decl + val   [11] cfg CCCD  [12] cfg user-desc
 *  [13,14] proto-ver decl + val    [15] ver CCCD  [16] ver user-desc
 */
#define ESP_PROV_VER_ATTR_IDX 14U

static struct bt_gatt_attr esp_prov_svc_attrs[] = {
	BT_GATT_PRIMARY_SERVICE(ESP_PROV_SVC_UUID),

	BT_GATT_CHARACTERISTIC(ESP_CHAR_UUID(0xFF50),
			       BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE | BT_GATT_CHRC_NOTIFY,
			       BT_GATT_PERM_READ | BT_GATT_PERM_WRITE | BT_GATT_PERM_PREPARE_WRITE,
			       prov_read_ep, prov_write_ep, (void *)EP_SCAN),
	BT_GATT_CCC(prov_ccc_cfg_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
	BT_GATT_DESCRIPTOR(BT_UUID_GATT_CUD, BT_GATT_PERM_READ, read_user_desc, NULL, "prov-scan"),

	BT_GATT_CHARACTERISTIC(ESP_CHAR_UUID(0xFF51),
			       BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE | BT_GATT_CHRC_NOTIFY,
			       BT_GATT_PERM_READ | BT_GATT_PERM_WRITE | BT_GATT_PERM_PREPARE_WRITE,
			       prov_read_ep, prov_write_ep, (void *)EP_SESS),
	BT_GATT_CCC(prov_ccc_cfg_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
	BT_GATT_DESCRIPTOR(BT_UUID_GATT_CUD, BT_GATT_PERM_READ, read_user_desc, NULL,
			   "prov-session"),

	BT_GATT_CHARACTERISTIC(ESP_CHAR_UUID(0xFF52),
			       BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE | BT_GATT_CHRC_NOTIFY,
			       BT_GATT_PERM_READ | BT_GATT_PERM_WRITE | BT_GATT_PERM_PREPARE_WRITE,
			       prov_read_ep, prov_write_ep, (void *)EP_CFG),
	BT_GATT_CCC(prov_ccc_cfg_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
	BT_GATT_DESCRIPTOR(BT_UUID_GATT_CUD, BT_GATT_PERM_READ, read_user_desc, NULL,
			   "prov-config"),

	BT_GATT_CHARACTERISTIC(ESP_CHAR_UUID(0xFF53),
			       BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE | BT_GATT_CHRC_NOTIFY,
			       BT_GATT_PERM_READ | BT_GATT_PERM_WRITE | BT_GATT_PERM_PREPARE_WRITE,
			       prov_read_ep, prov_write_ep, (void *)EP_VER),
	BT_GATT_CCC(prov_ccc_cfg_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
	BT_GATT_DESCRIPTOR(BT_UUID_GATT_CUD, BT_GATT_PERM_READ, read_user_desc, NULL, "proto-ver"),
};

static struct bt_gatt_service esp_prov_svc = {
	.attrs = esp_prov_svc_attrs,
	.attr_count = ARRAY_SIZE(esp_prov_svc_attrs),
};

static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	BT_DATA_BYTES(BT_DATA_UUID128_ALL, 0x07, 0xed, 0x9b, 0x2d, 0x0f, 0x06, 0x7c, 0x87, 0x9b, 0x43,
		      0x43, 0x6b, 0x4d, 0x24, 0x75, 0x17),
};

static struct bt_data sd[] = {
	BT_DATA(BT_DATA_NAME_COMPLETE, ESP_PROV_SOFTAP_SSID, sizeof(ESP_PROV_SOFTAP_SSID) - 1),
};

static size_t bt_data_payload_len(const struct bt_data *data, size_t count)
{
	size_t len = 0U;

	for (size_t i = 0U; i < count; i++) {
		len += data[i].data_len;
	}
	return len;
}

static int ble_adv_start_internal(void);
static void ble_adv_restart_work_fn(struct k_work *work);

/* Defer off the disconnect callback so the host/controller can finish teardown before
 * adv_start; avoids piling onto BT RX coop while main would otherwise starve.
 * ESP32+SoftAP coexistence: too short a delay correlated with rapid connect/0x13 churn.
 */
#define BLE_ADV_RESTART_DELAY_MS 150U

K_WORK_DELAYABLE_DEFINE(ble_adv_restart_work, ble_adv_restart_work_fn);

static void ble_idle_after_disc_work_fn(struct k_work *work);

K_WORK_DELAYABLE_DEFINE(ble_idle_after_disc_work, ble_idle_after_disc_work_fn);

/* Proto-ver notify was inline in ble_connected (BT RX thread). With SoftAP+logging, stack
 * pressure there correlated with illegal-instruction faults in z_swap; run notify on syswq.
 */
static void ble_proto_ver_notify_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);

	if (ble_conn == NULL) {
		return;
	}

	(void)bt_gatt_notify(ble_conn, &esp_prov_svc.attrs[ESP_PROV_VER_ATTR_IDX],
			   ESP_PROV_JSON_PROTO_VER, sizeof(ESP_PROV_JSON_PROTO_VER) - 1U);
}

K_WORK_DEFINE(ble_proto_ver_notify_work, ble_proto_ver_notify_work_fn);

static void ble_idle_after_disc_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);

	if (esp_prov_transport_choice() == ESP_PROV_TP_SOFTAP) {
		return;
	}
	if (esp_prov_shared_is_finished() || esp_prov_shared_stop_requested()) {
		return;
	}
	if (ble_conn != NULL) {
		return;
	}
	if (!ble_had_central_link) {
		return;
	}
	LOG_WRN("BLE provisioning peer disconnected -- ending session (no reconnect within %u s)",
		(unsigned int)CONFIG_ESP_PROV_BLE_IDLE_AFTER_DISCONNECT_SEC);
	esp_prov_cancel_system();
}

static int ble_adv_start_internal(void)
{
	int err;

	LOG_DBG("BLE adv start request: name=\"" ESP_PROV_SOFTAP_SSID
		"\" ad_items=%u ad_payload=%u sd_items=%u sd_payload=%u gatt_registered=%d",
		(unsigned int)ARRAY_SIZE(ad), (unsigned int)bt_data_payload_len(ad, ARRAY_SIZE(ad)),
		(unsigned int)ARRAY_SIZE(sd), (unsigned int)bt_data_payload_len(sd, ARRAY_SIZE(sd)),
		(int)atomic_get(&prov_gatt_registered));

	err = bt_le_adv_start(BT_LE_ADV_CONN_FAST_1, ad, ARRAY_SIZE(ad), sd, ARRAY_SIZE(sd));

	if (err != 0) {
		LOG_WRN("BLE adv start failed: err=%d", err);
		return err;
	}
	atomic_set(&ble_adv_on, 1);
	LOG_INF("BLE provisioning advertising as \"" ESP_PROV_SOFTAP_SSID "\"");
	LOG_DBG("BLE adv start ok: ble_adv_on=%d", (int)atomic_get(&ble_adv_on));
	return 0;
}

static void ble_adv_restart_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);

	if (esp_prov_transport_choice() == ESP_PROV_TP_SOFTAP) {
		return;
	}
	if (esp_prov_shared_is_finished() || esp_prov_shared_stop_requested()) {
		return;
	}
	if (ble_conn != NULL) {
		return;
	}
	{
		int ar = ble_adv_start_internal();

		if (ar != 0) {
			LOG_WRN("BLE: advertising restart after disconnect failed (%d); SoftAP still active",
				ar);
		} else {
			LOG_INF("BLE: advertising restarted -- phone can reconnect until session timeout");
		}
	}
}

static void ble_connected(struct bt_conn *conn, uint8_t err)
{
	if (err != 0U) {
		LOG_WRN("BLE connect failed hci_err=0x%02x %s", err, bt_hci_err_to_str(err));
		return;
	}
	if (atomic_get(&prov_gatt_registered) == 0) {
		return;
	}
	if (ble_conn != NULL) {
		LOG_WRN("BLE: second central tried to connect; disconnecting it (only one client)");
		(void)bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
		return;
	}
	/*
	 * Transport selection moved to prov_write_ep: a bare connect (or a phone that
	 * only reads /proto-ver) no longer commits the device to BLE. SoftAP stays
	 * available until the first real protocomm WRITE on this link.
	 */
#if IS_ENABLED(CONFIG_BT_ESP32)
	(void)esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_CONN_HDL0, ble_pwr_level_from_dbm(CONFIG_ESP32_PHY_MAX_TX_POWER));
#endif
	ble_conn = bt_conn_ref(conn);
	ble_sess_id = (uint32_t)(uintptr_t)conn ^ (uint32_t)k_uptime_get_32();
	if (ble_sess_id == 0U) {
		ble_sess_id = 1U;
	}
	(void)k_work_cancel_delayable(&ble_idle_after_disc_work);
	if (esp_prov_sec1_transport_open(esp_prov_sec1_ble(), ble_sess_id) != 0) {
		LOG_ERR("BLE: sec1 transport_open failed (RNG) -- disconnecting central");
		bt_conn_unref(ble_conn);
		ble_conn = NULL;
		ble_had_central_link = false;
		(void)bt_conn_disconnect(conn, BT_HCI_ERR_LOCALHOST_TERM_CONN);
		return;
	}
	ble_had_central_link = true;
	ble_cfg_finish_signal_after_read = false;
	LOG_INF("BLE provisioning peer connected");
#if IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)
	LOG_DBG("[prov-c] BLE LINK up");
#endif

	/*
	 * Send initial proto-ver notify. The phone may have a cached CCCD subscription
	 * from a prior session and be waiting for this before sending writes.
	 * If not subscribed yet, bt_gatt_notify returns -EINVAL silently.
	 * Submitted to the system workqueue: ble_connected runs on the BT RX thread, which
	 * has limited stack (see CONFIG_BT_RX_STACK_SIZE in the shell sample).
	 */
	(void)k_work_submit(&ble_proto_ver_notify_work);
}

static void ble_disconnected(struct bt_conn *conn, uint8_t reason)
{
	if (conn == ble_conn) {
		(void)esp_prov_sec1_transport_close(esp_prov_sec1_ble(), ble_sess_id);
		bt_conn_unref(ble_conn);
		ble_conn = NULL;
		LOG_INF("BLE provisioning disconnected reason=0x%02x %s", reason,
			bt_hci_err_to_str(reason));
#if IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)
		LOG_DBG("[prov-c] BLE LINK down reason=0x%02x", reason);
#endif
		/*
		 * Connectable advertising stops on link-up; without restarting, the phone cannot
		 * reconnect until the whole session ends. Schedule restart on the system workqueue
		 * so we are not in the middle of the host disconnect path.
		 *
		 * BLE-committed branch: skip re-adv (phone is done with prov); auto-cancel after
		 * the grace window so the user does not need to press cancel manually.
		 * Uncommitted and SoftAP-committed branches: re-adv + optional idle cancel (legacy).
		 */
		if (esp_prov_transport_choice() == ESP_PROV_TP_SOFTAP) {
			return;
		}
		if (esp_prov_transport_choice() == ESP_PROV_TP_BLE) {
			/* Committed BLE: no re-adv; schedule auto-cancel after grace window. */
			if (CONFIG_ESP_PROV_BLE_IDLE_AFTER_DISCONNECT_SEC > 0 &&
			    !esp_prov_shared_is_finished() && !esp_prov_shared_stop_requested()) {
				(void)k_work_cancel_delayable(&ble_idle_after_disc_work);
				(void)k_work_reschedule(
					&ble_idle_after_disc_work,
					K_SECONDS(CONFIG_ESP_PROV_BLE_IDLE_AFTER_DISCONNECT_SEC));
			}
			return;
		}
		/* Uncommitted (ESP_PROV_TP_NONE): re-adv so phone can reconnect. */
		if (!esp_prov_shared_is_finished() && !esp_prov_shared_stop_requested()) {
			(void)k_work_reschedule(&ble_adv_restart_work, K_MSEC(BLE_ADV_RESTART_DELAY_MS));
		}
#if CONFIG_ESP_PROV_BLE_IDLE_AFTER_DISCONNECT_SEC > 0
		(void)k_work_cancel_delayable(&ble_idle_after_disc_work);
		if (ble_had_central_link &&
		    !esp_prov_shared_is_finished() && !esp_prov_shared_stop_requested()) {
			(void)k_work_reschedule(
				&ble_idle_after_disc_work,
				K_SECONDS(CONFIG_ESP_PROV_BLE_IDLE_AFTER_DISCONNECT_SEC));
		}
#endif
	}
}

BT_CONN_CB_DEFINE(prov_conn_cb) = {
	.connected = ble_connected,
	.disconnected = ble_disconnected,
};

int esp_prov_ble_start(void)
{
	int err;

	ble_cfg_finish_signal_after_read = false;
	ble_had_central_link = false;
	(void)k_work_cancel_delayable(&ble_idle_after_disc_work);

	rsp_scan_len = 0U;
	rsp_sess_len = 0U;
	rsp_cfg_len = 0U;

	LOG_DBG("BLE provisioning start: setting BT name to \"" ESP_PROV_SOFTAP_SSID "\"");
	err = bt_set_name(ESP_PROV_SOFTAP_SSID);
	if (err != 0) {
		LOG_WRN("bt_set_name prov ssid failed %d", err);
	} else {
		LOG_DBG("BLE provisioning start: bt_set_name ok");
	}

	LOG_DBG("BLE provisioning start: registering GATT service attr_count=%u",
		(unsigned int)esp_prov_svc.attr_count);
	err = bt_gatt_service_register(&esp_prov_svc);
	if (err != 0) {
		LOG_ERR("prov GATT register %d", err);
		return err;
	}
	atomic_set(&prov_gatt_registered, 1);
	LOG_DBG("BLE provisioning start: GATT service registered");

	err = ble_adv_start_internal();
	if (err != 0) {
		LOG_ERR("BLE adv start %d", err);
		(void)bt_gatt_service_unregister(&esp_prov_svc);
		atomic_set(&prov_gatt_registered, 0);
		return err;
	}
#if IS_ENABLED(CONFIG_ESP_PROV_DEVELOPER_TRANSPORT)
	LOG_INF("BLE: no DNS/TCP MSG_PEEK tap (SoftAP-only: CONFIG_ESP_PROV_SOFTAP_NET_HEX); "
		"use PKT_LOG/CONSOLE_PROBE/APP_TRACE for GATT PDUs");
#endif
	return 0;
}

void esp_prov_ble_stop(void)
{
	(void)k_work_cancel_delayable(&ble_adv_restart_work);
	(void)k_work_cancel_delayable(&ble_idle_after_disc_work);
	if (atomic_get(&ble_adv_on) != 0) {
		(void)bt_le_adv_stop();
		atomic_set(&ble_adv_on, 0);
	}
	if (ble_conn != NULL) {
		(void)bt_conn_disconnect(ble_conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	}
	if (atomic_get(&prov_gatt_registered) != 0) {
		(void)bt_gatt_service_unregister(&esp_prov_svc);
		atomic_set(&prov_gatt_registered, 0);
	}
}

int esp_prov_bt_enable(void)
{
	static atomic_t enabled;
	static bool settings_loaded;
	int err;

	if (atomic_get(&enabled) != 0) {
		return 0;
	}
	err = bt_enable(NULL);
	if (err != 0) {
		return err;
	}
#if IS_ENABLED(CONFIG_BT_ESP32)
	esp_prov_ble_apply_tx_power();
#endif
	if (IS_ENABLED(CONFIG_SETTINGS) && !settings_loaded) {
		err = settings_load();
		if (err != 0) {
			LOG_WRN("settings_load failed (%d)", err);
		}
		settings_loaded = true;
	}
	atomic_set(&enabled, 1);
	return 0;
}

#else /* !CONFIG_ESP_PROV_USE_BLE */

/*
 * BLE provisioning transport disabled at build time. Provide minimal stubs so that
 * esp_prov_run.c (and the app coordinator) can call these entry points unconditionally.
 * The routine still skips the BLE bring-up at runtime when CONFIG_ESP_PROV_USE_BLE=n,
 * but keeping the symbols means no further #if guards leak into the call sites.
 */

int esp_prov_ble_start(void)
{
	return 0;
}

void esp_prov_ble_stop(void)
{
}

int esp_prov_bt_enable(void)
{
	return 0;
}

#endif /* CONFIG_ESP_PROV_USE_BLE */
