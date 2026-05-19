/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Console menu sample for esp_provisioning (see README.md).
 */

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include <zephyr/console/console.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/reboot.h>

#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/wifi.h>
#include <zephyr/net/wifi_credentials.h>
#include <zephyr/net/wifi_mgmt.h>

#include "esp_prov.h"

LOG_MODULE_REGISTER(esp_provisioning_shell, LOG_LEVEL_ERR);

#define WIFI_CONNECT_WAIT_MS 30000

static bool last_prov_ok;
static struct esp_wifi_credentials last_creds;

static volatile int wifi_connect_status = -1;

static struct net_mgmt_event_callback wifi_connect_cb;

static void print_sta_ipv4_info(void);

static void wifi_connect_result_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
					struct net_if *iface)
{
	const struct wifi_status *st = (const struct wifi_status *)cb->info;

	ARG_UNUSED(iface);

	if (mgmt_event != NET_EVENT_WIFI_CONNECT_RESULT) {
		return;
	}

	wifi_connect_status = st->status;
}

static void print_menu(void)
{
	printk("\n");
	printk("1) Start provisioning\n");
	printk("2) Test WiFi connection\n");
	printk("3) Show current credentials\n");
	printk("4) Save WiFi credentials and reboot\n");
	printk("5) Reboot only\n");
	printk("(Enter or Esc: show menu again)\n");
	printk("Enter choice 1-5: ");
}

static char read_menu_digit(void)
{
	uint8_t c;

	for (;;) {
		c = console_getchar();
		if (c >= '1' && c <= '5') {
			printk("%c\n", c);
			return (char)c;
		}
		/* Refresh prompt when terminal did not reboot (e.g. after 4)) or user
		 * wants the menu again without picking an option yet.
		 */
		if (c == '\r' || c == '\n' || c == 0x1b) {
			print_menu();
			continue;
		}
		printk("\nInvalid key. ");
		print_menu();
	}
}

static void fill_connect_from_esp(const struct esp_wifi_credentials *creds,
				  struct wifi_connect_req_params *params)
{
	memset(params, 0, sizeof(*params));

	params->ssid = (const uint8_t *)creds->ssid;
	params->ssid_length = strlen(creds->ssid);

	if (strlen(creds->psk) > 0U) {
		params->psk = (const uint8_t *)creds->psk;
		params->psk_length = strlen(creds->psk);
		params->security = WIFI_SECURITY_TYPE_PSK;
	} else {
		params->security = WIFI_SECURITY_TYPE_NONE;
	}

	params->channel = WIFI_CHANNEL_ANY;
	params->band = WIFI_FREQ_BAND_2_4_GHZ;
}

static void fill_connect_from_stored_personal(const struct wifi_credentials_personal *cp,
					       struct wifi_connect_req_params *params)
{
	memset(params, 0, sizeof(*params));

	params->ssid = (const uint8_t *)cp->header.ssid;
	params->ssid_length = cp->header.ssid_len;

	if (cp->password_len > 0U) {
		params->psk = (const uint8_t *)cp->password;
		params->psk_length = cp->password_len;
	}

	params->security = cp->header.type;
	params->channel = WIFI_CHANNEL_ANY;
	params->band = WIFI_FREQ_BAND_2_4_GHZ;
}

struct first_ssid_ctx {
	bool filled;
	char ssid[WIFI_SSID_MAX_LEN];
	size_t ssid_len;
};

static void foreach_first_ssid_cb(void *user_data, const char *ssid, size_t ssid_len)
{
	struct first_ssid_ctx *ctx = user_data;

	if (ctx->filled) {
		return;
	}

	if (ssid_len == 0U || ssid_len >= WIFI_SSID_MAX_LEN) {
		return;
	}

	memcpy(ctx->ssid, ssid, ssid_len);
	ctx->ssid[ssid_len] = '\0';
	ctx->ssid_len = ssid_len;
	ctx->filled = true;
}

/*
 * cp_buf is owned by the caller and must outlive the subsequent
 * NET_REQUEST_WIFI_CONNECT call: fill_connect_from_stored_personal() stores
 * pointers into cp_buf->header.ssid / cp_buf->password into params, and the
 * Wi-Fi driver only memcpy's those buffers when it handles the connect
 * request, not when this resolver returns.
 */
static int resolve_connect_params(struct wifi_connect_req_params *params,
				  struct wifi_credentials_personal *cp_buf)
{
	struct first_ssid_ctx ctx = { 0 };

	if (last_prov_ok) {
		fill_connect_from_esp(&last_creds, params);
		return 0;
	}

	if (wifi_credentials_is_empty()) {
		return -ENOENT;
	}

	wifi_credentials_for_each_ssid(foreach_first_ssid_cb, &ctx);

	if (!ctx.filled) {
		return -ENOENT;
	}

	memset(cp_buf, 0, sizeof(*cp_buf));

	if (wifi_credentials_get_by_ssid_personal_struct(ctx.ssid, ctx.ssid_len, cp_buf) != 0) {
		return -EIO;
	}

	fill_connect_from_stored_personal(cp_buf, params);
	return 0;
}

static int wifi_do_connect(struct wifi_connect_req_params *params)
{
	struct net_if *sta = net_if_get_wifi_sta();
	int ret;
	int64_t deadline;

	if (sta == NULL) {
		printk("No STA interface\n");
		return -ENODEV;
	}

	wifi_connect_status = -1;

	ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, sta, params, sizeof(struct wifi_connect_req_params));
	if (ret == -EALREADY) {
		/* Race: status query said the link was idle but the driver had
		 * already (re-)entered CONNECTING/CONNECTED. The driver also
		 * raised a synthetic WIFI_STATUS_CONN_FAIL for our request, so
		 * don't trust wifi_connect_status here.
		 */
		printk("WiFi: connect already in progress (driver state).\n");
		return -EALREADY;
	}
	if (ret != 0) {
		printk("NET_REQUEST_WIFI_CONNECT failed: %d\n", ret);
		return ret;
	}

	deadline = k_uptime_get() + WIFI_CONNECT_WAIT_MS;
	while (k_uptime_get() < deadline && wifi_connect_status == -1) {
		k_sleep(K_MSEC(100));
	}

	if (wifi_connect_status != 0) {
		printk("WiFi connect failed (status=%d)\n", wifi_connect_status);
		return -EIO;
	}

	printk("WiFi connected\n");
	return 0;
}

static void wait_for_link_completed(struct net_if *sta)
{
	struct wifi_iface_status iface_st;
	int64_t deadline = k_uptime_get() + WIFI_CONNECT_WAIT_MS;

	for (;;) {
		memset(&iface_st, 0, sizeof(iface_st));
		if (net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, sta, &iface_st, sizeof(iface_st)) != 0) {
			printk("Could not query Wi-Fi iface status\n");
			return;
		}
		if (iface_st.state == WIFI_STATE_COMPLETED ||
		    iface_st.state == WIFI_STATE_DISCONNECTED ||
		    k_uptime_get() >= deadline) {
			break;
		}
		k_sleep(K_MSEC(200));
	}

	if (iface_st.state == WIFI_STATE_COMPLETED) {
		printk("WiFi connected to \"%.*s\" (%s)\n", (int)iface_st.ssid_len, iface_st.ssid,
		       wifi_state_txt(iface_st.state));
		print_sta_ipv4_info();
	} else {
		printk("WiFi not connected yet (state=%s)\n", wifi_state_txt(iface_st.state));
	}
}

static void print_sta_ipv4_info(void)
{
	struct net_if *sta = net_if_get_wifi_sta();
	struct net_in_addr *addr;
	char buf[NET_IPV4_ADDR_LEN];
	struct net_in_addr mask;
	struct net_in_addr gw;

	if (sta == NULL) {
		return;
	}

	addr = net_if_ipv4_get_global_addr(sta, NET_ADDR_PREFERRED);
	if (addr == NULL) {
		printk("STA: no global IPv4 address yet\n");
		return;
	}

	(void)net_addr_ntop(AF_INET, addr, buf, sizeof(buf));
	printk("STA IPv4: %s\n", buf);

	mask = net_if_ipv4_get_netmask_by_addr(sta, addr);
	(void)net_addr_ntop(AF_INET, &mask, buf, sizeof(buf));
	printk("STA netmask: %s\n", buf);

	gw = net_if_ipv4_get_gw(sta);
	(void)net_addr_ntop(AF_INET, &gw, buf, sizeof(buf));
	printk("STA gateway: %s\n", buf);
}

static bool confirm_secrets(void)
{
	uint8_t c;

	printk("\n*** WARNING: SSID and password will be printed in plaintext on this console.\n");
	printk("Press Y to continue, any other key to cancel: ");

	for (;;) {
		c = console_getchar();
		if (c == 'y' || c == 'Y') {
			printk("Y\n");
			return true;
		}
		if (c == '\r' || c == '\n') {
			continue;
		}
		printk("\nCancelled.\n");
		return false;
	}
}

static void print_each_stored_cb(void *user_data, const char *ssid, size_t ssid_len)
{
	struct wifi_credentials_personal cp;

	ARG_UNUSED(user_data);

	memset(&cp, 0, sizeof(cp));
	if (wifi_credentials_get_by_ssid_personal_struct(ssid, ssid_len, &cp) != 0) {
		return;
	}

	printk("  SSID: %.*s\n", (int)cp.header.ssid_len, cp.header.ssid);
	printk("  PSK:  %.*s\n", (int)cp.password_len, cp.password);
}

static void print_stored_credentials_plain_named(void)
{
	if (wifi_credentials_is_empty()) {
		printk("Stored credentials: (none)\n");
		return;
	}

	printk("Stored credentials:\n");
	wifi_credentials_for_each_ssid(print_each_stored_cb, NULL);
}

static void option_show_credentials(void)
{
	if (!confirm_secrets()) {
		return;
	}

	if (last_prov_ok) {
		printk("RAM (last provisioning):\n");
		printk("  SSID: %s\n", last_creds.ssid);
		printk("  PSK:  %s\n", last_creds.psk);
	} else {
		printk("RAM (last provisioning): (none)\n");
	}

	print_stored_credentials_plain_named();

	print_sta_ipv4_info();
}

static void option_save_reboot(void)
{
	int ret;

	if (!last_prov_ok) {
		if (wifi_credentials_is_empty()) {
			printk("No new provisioning detected, and no stored credentials. "
			       "Run 1) provisioning first.\n");
		} else {
			printk("No new provisioning detected, nothing to save. "
			       "(Stored credentials already in NVS — use 3) to inspect.)\n");
		}
		return;
	}

	{
		enum wifi_security_type sec =
			(strlen(last_creds.psk) > 0U) ? WIFI_SECURITY_TYPE_PSK : WIFI_SECURITY_TYPE_NONE;

		ret = wifi_credentials_set_personal(last_creds.ssid, strlen(last_creds.ssid), sec,
						    NULL, 0, last_creds.psk, strlen(last_creds.psk),
						    0U, 0U, 0U);
	}
	if (ret != 0) {
		printk("wifi_credentials_set_personal failed: %d\n", ret);
		return;
	}

	printk("Saved. Rebooting...\n");
	k_sleep(K_MSEC(100));
	sys_reboot(SYS_REBOOT_COLD);
}

static void option_reboot_only(void)
{
	printk("Rebooting...\n");
	k_sleep(K_MSEC(100));
	sys_reboot(SYS_REBOOT_COLD);
}

static void option_provisioning(void)
{
	struct net_if *sta = net_if_get_wifi_sta();
	struct wifi_iface_status iface_st;
	int err;

	/* Without APSTA, or when STA is already associated on a single net_if,
	 * SoftAP setup can fail ("AP IPv4/DHCP setup failed"). Tear STA down so
	 * esp_prov_run() sees a clean slate (still useful with AP_STA=y).
	 */
	if (sta != NULL) {
		memset(&iface_st, 0, sizeof(iface_st));
		if (net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, sta, &iface_st,
			     sizeof(iface_st)) == 0 &&
		    iface_st.state >= WIFI_STATE_SCANNING) {
			printk("Disconnecting STA (was %s) before bringing up SoftAP "
			       "for provisioning...\n",
			       wifi_state_txt(iface_st.state));
			(void)net_mgmt(NET_REQUEST_WIFI_DISCONNECT, sta, NULL, 0);
			/* Brief settle so the driver leaves CONNECTED/CONNECTING
			 * before esp_prov_run() asks for AP mode.
			 */
			k_sleep(K_MSEC(500));
		}
	}

	err = esp_prov_run(&last_creds);
	switch (err) {
	case ESP_PROV_OK:
		last_prov_ok = true;
		printk("Provisioning OK\n");
		break;
	case ESP_PROV_ERR_CANCELLED:
		last_prov_ok = false;
		printk("Provisioning cancelled\n");
		break;
	case ESP_PROV_ERR_TIMEOUT:
		last_prov_ok = false;
		printk("Provisioning timeout\n");
		break;
	case ESP_PROV_ERR_NOT_IMPLEMENTED:
		last_prov_ok = false;
		printk("Provisioning not built\n");
		break;
	default:
		last_prov_ok = false;
		printk("Provisioning failed: %d\n", err);
		break;
	}
}

static void option_test_wifi(void)
{
	struct wifi_connect_req_params params;
	/* Backing storage for stored-credentials path; must outlive
	 * wifi_do_connect() because params->ssid/psk point into it.
	 */
	struct wifi_credentials_personal cp;
	struct net_if *sta = net_if_get_wifi_sta();
	struct wifi_iface_status iface_st;
	int ret;

	if (sta == NULL) {
		printk("No STA interface\n");
		return;
	}

	/* If the driver is already mid-join or associated (e.g. provisioning
	 * just test-connected, or CONFIG_ESP32_WIFI_STA_RECONNECT brought the
	 * link back up after a transient drop), a fresh NET_REQUEST_WIFI_CONNECT
	 * would just return -EALREADY. Wait for the existing attempt to settle
	 * and report its outcome instead.
	 *
	 * Threshold is >= WIFI_STATE_SCANNING (not _AUTHENTICATING) because the
	 * ESP32 Wi-Fi driver collapses its internal STA_CONNECTING state into
	 * WIFI_STATE_SCANNING in NET_REQUEST_WIFI_IFACE_STATUS — that's exactly
	 * the state that triggers -EALREADY from esp32_wifi_connect().
	 */
	memset(&iface_st, 0, sizeof(iface_st));
	if (net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, sta, &iface_st, sizeof(iface_st)) == 0 &&
	    iface_st.state >= WIFI_STATE_SCANNING) {
		printk("Wi-Fi link busy (state=%s, ssid=\"%.*s\"); waiting for it to settle.\n",
		       wifi_state_txt(iface_st.state), (int)iface_st.ssid_len, iface_st.ssid);
		wait_for_link_completed(sta);
		return;
	}

	ret = resolve_connect_params(&params, &cp);
	if (ret == -ENOENT) {
		printk("No credentials. Run 1) provisioning first (then optionally 4) save).\n");
		return;
	}
	if (ret != 0) {
		printk("Could not load credentials: %d\n", ret);
		return;
	}

	ret = wifi_do_connect(&params);
	if (ret == 0) {
		print_sta_ipv4_info();
	} else if (ret == -EALREADY) {
		/* Race after the state query; pick up the existing attempt. */
		wait_for_link_completed(sta);
	} else {
		printk("Connect failed: %d\n", ret);
	}
}

int main(void)
{
	console_init();

	net_mgmt_init_event_callback(&wifi_connect_cb, wifi_connect_result_handler,
				    NET_EVENT_WIFI_CONNECT_RESULT);
	net_mgmt_add_event_callback(&wifi_connect_cb);

	printk("esp_provisioning_shell\n");
#if IS_ENABLED(CONFIG_ESP_PROV_USE_BLE) && IS_ENABLED(CONFIG_ESP_PROV_USE_SOFTAP)
	printk("Provisioning transports: BLE + SoftAP\n");
#elif IS_ENABLED(CONFIG_ESP_PROV_USE_BLE)
	printk("Provisioning transports: BLE only\n");
#elif IS_ENABLED(CONFIG_ESP_PROV_USE_SOFTAP)
	printk("Provisioning transports: SoftAP only\n");
#endif

	for (;;) {
		print_menu();

		switch (read_menu_digit()) {
		case '1':
			option_provisioning();
			break;
		case '2':
			option_test_wifi();
			break;
		case '3':
			option_show_credentials();
			break;
		case '4':
			option_save_reboot();
			break;
		case '5':
			option_reboot_only();
			break;
		default:
			break;
		}
	}

	return 0;
}
