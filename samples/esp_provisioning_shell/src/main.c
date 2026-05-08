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
	printk("Enter choice 1-4: ");
}

static char read_menu_digit(void)
{
	uint8_t c;

	for (;;) {
		c = console_getchar();
		if (c >= '1' && c <= '4') {
			printk("%c\n", c);
			return (char)c;
		}
		if (c == '\r' || c == '\n') {
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

static int resolve_connect_params(struct wifi_connect_req_params *params)
{
	struct first_ssid_ctx ctx = { 0 };
	struct wifi_credentials_personal cp;

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

	memset(&cp, 0, sizeof(cp));

	if (wifi_credentials_get_by_ssid_personal_struct(ctx.ssid, ctx.ssid_len, &cp) != 0) {
		return -EIO;
	}

	fill_connect_from_stored_personal(&cp, params);
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
		printk("Run 1) provisioning first.\n");
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

static void option_provisioning(void)
{
	int err;

	if (IS_ENABLED(CONFIG_ESP_PROV_USE_BLE)) {
		err = esp_prov_bt_enable();
		if (err != 0) {
			LOG_ERR("esp_prov_bt_enable failed: %d", err);
			return;
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
	int ret;

	ret = resolve_connect_params(&params);
	if (ret == -ENOENT) {
		printk("No credentials. Run 1) provisioning first (then optionally 4) save).\n");
		return;
	}
	if (ret != 0) {
		printk("Could not load credentials: %d\n", ret);
		return;
	}

	ret = wifi_do_connect(&params);
	if (ret != 0) {
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
		default:
			break;
		}
	}

	return 0;
}
