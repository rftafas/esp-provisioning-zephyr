/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Dual transport: SoftAP + HTTP protocomm and BLE GATT protocomm (first to finish wins).
 */

#include "esp_prov.h"
#include "esp_prov_internal.h"
#include "prov_controller.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/autoconf.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/util.h>
#include <zephyr/net/dhcpv4_server.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/random/random.h>

LOG_MODULE_REGISTER(esp_prov_softap, CONFIG_ESP_PROV_LOG_LEVEL);

#if IS_ENABLED(CONFIG_ESP_PROV_SOFTAP_NET_HEX)
/* Multi-line hex (16 bytes/line) for DNS/TCP peek -- debug only. */
static void prov_net_hexdump(const char *tag, const uint8_t *data, size_t len)
{
	const size_t row = 16U;
	char line[3U * 16U + 4U];

	if (len == 0U) {
		LOG_DBG("%s (empty)", tag);
		return;
	}
	for (size_t off = 0U; off < len; off += row) {
		size_t n = MIN(row, len - off);
		size_t p = 0U;

		for (size_t i = 0U; i < n && p + 4U < sizeof(line); i++) {
			p += (size_t)snprintf(line + p, sizeof(line) - p, "%02x ", data[off + i]);
		}
		LOG_DBG("%s +%04u: %s", tag, (unsigned int)off, line);
	}
}

static void prov_tcp_peek_log(int cfd, const char *tag, size_t max_len)
{
	uint8_t buf[384];
	size_t cap = MIN(sizeof(buf), max_len);
	int n = zsock_recv(cfd, buf, cap, ZSOCK_MSG_PEEK);

	if (n < 0) {
		LOG_WRN("%s MSG_PEEK err=%d", tag, errno);
		return;
	}
	if (n == 0) {
		LOG_DBG("%s MSG_PEEK 0 bytes (no queued data yet)", tag);
		return;
	}
	LOG_DBG("%s MSG_PEEK %d byte(s) (not consumed)", tag, n);
	prov_net_hexdump(tag, buf, (size_t)n);
}
#endif

/* SoftAP HTTP body hex preview -- payload bytes only, gated on the same "Packet sniffing"
 * Kconfig choice as the BLE payload hex inside esp_prov_trace_app() (CONFIG_ESP_PROV_APP_TRACE,
 * set only by ESP_PROV_DIAG_PACKETS). Extended debug (ESP_PROV_DIAG_EXTENDED -> PKT_LOG) is the
 * lighter PDU-summary tier and must not emit raw payload bytes -- the choice's help text warns
 * "may expose credentials". */
#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE)
static void http_log_hex(const char *tag, const uint8_t *d, size_t n)
{
	char line[32U * 3U + 4U];
	size_t show;
	size_t pos = 0U;

	if (n == 0U) {
		LOG_DBG("HTTP %s len=0", tag);
		return;
	}
	show = MIN(n, 32U);
	for (size_t i = 0U; i < show && pos + 3U < sizeof(line); i++) {
		pos += (size_t)snprintf(line + pos, sizeof(line) - pos, "%02x ", d[i]);
	}
	LOG_DBG("HTTP %s len=%zu hex %s", tag, n, line);
	if (n > show) {
		LOG_DBG("HTTP %s ... (%zu more bytes)", tag, n - show);
	}
}
#endif

#define LISTEN_PORT     80
/* Android / Chrome may probe HTTPS on the resolved "internet check" IP before or
 * instead of HTTP :80 -- accept and drop so we see TCP (TLS handshake will fail; PoP uses :80).
 */
#define TLS_PROBE_PORT 443
#define HTTP_HDR_MAX    600
#define HTTP_BODY_MAX   4096

/*
 * SoftAP HTTP per-session scratch (~13.5 KiB total) lives on the prov-http worker
 * stack (see CONFIG_ESP_PROV_HTTP_WORKER_STACK_SIZE in prj.conf): hdr + body + resp
 * in http_handle_client(), plus an extra work[HTTP_BODY_MAX] declared inside the
 * prov-config / prov-scan branches (mutually exclusive within one HTTP request).
 *
 * The earlier heap-backed prov_http_scratch (~13.5 KiB k_malloc) competed with the
 * Wi-Fi adapter's wifi_malloc() on CONFIG_HEAP_MEM_POOL_SIZE during AP+BLE peaks
 * and starved RX buffers as soon as a phone joined SoftAP -- see journal entry
 * "SoftAP regression: prov scratch on heap starved Wi-Fi adapter (2026-04-29)".
 */

static uint32_t s_cookie_id;
static bool s_have_cookie;

#if IS_ENABLED(CONFIG_ESP_PROV_USE_SOFTAP)

static struct net_if *s_ap;

static struct net_mgmt_event_callback s_ap_events_cb;

struct dhcp_lease_count {
	int slots;
	int allocated;
};

/* Format lease->client_id for logs (Ethernet chaddr is htype 1 + 6 octets). */
static void dhcp_format_client_id(char *out, size_t out_sz, const struct dhcpv4_client_id *cid)
{
	if (cid->len == 0U || out_sz == 0U) {
		(void)snprintf(out, out_sz, "(no client-id)");
		return;
	}
	if (cid->len == 7U && cid->buf[0] == 1U) {
		(void)snprintf(out, out_sz, "MAC %02x:%02x:%02x:%02x:%02x:%02x", cid->buf[1],
			       cid->buf[2], cid->buf[3], cid->buf[4], cid->buf[5], cid->buf[6]);
		return;
	}
	size_t pos = 0U;

	for (size_t i = 0U; i < cid->len && pos + 4U < out_sz; i++) {
		pos += (size_t)snprintf(out + pos, out_sz - pos, "%02x%s", cid->buf[i],
					(i + 1U < cid->len) ? ":" : "");
	}
}

static void dhcp_lease_trace_cb(struct net_if *iface, struct dhcpv4_addr_slot *lease, void *user_data)
{
	struct dhcp_lease_count *c = user_data;
	const char *st = "?";
	char addrstr[NET_IPV4_ADDR_LEN];
	char cidstr[3U * DHCPV4_CLIENT_ID_MAX_SIZE + 8U];
	int64_t now_ms = k_uptime_get();

	ARG_UNUSED(iface);
	c->slots++;

	switch (lease->state) {
	case DHCPV4_SERVER_ADDR_RESERVED:
		st = "RESERVED (Offer sent, waiting Request/ACK)";
		break;
	case DHCPV4_SERVER_ADDR_ALLOCATED:
		st = "ALLOCATED (client may use this IPv4)";
		c->allocated++;
		break;
	case DHCPV4_SERVER_ADDR_DECLINED:
		st = "DECLINED";
		break;
	default:
		break;
	}

	(void)net_addr_ntop(AF_INET, &lease->addr, addrstr, sizeof(addrstr));
	dhcp_format_client_id(cidstr, sizeof(cidstr), &lease->client_id);

	LOG_DBG("DHCP server [+%lld ms] slot: %s | IPv4 %s | %s | lease_time=%u s", (long long)now_ms,
		st, addrstr, cidstr, (unsigned int)lease->lease_time);

	if (lease->state == DHCPV4_SERVER_ADDR_ALLOCATED) {
		LOG_DBG("DHCP server: assigned %s to %s (fully bound)", addrstr, cidstr);
	}
}

static void prov_log_dhcp_leases(const char *reason)
{
	struct dhcp_lease_count c = { 0, 0 };

	if (s_ap == NULL) {
		return;
	}

	LOG_DBG("DHCP server: lease snapshot (%s), pool %s .. +%u addr(s):", reason,
		CONFIG_ESP_PROV_SOFTAP_DHCP_POOL_BASE, (unsigned int)CONFIG_NET_DHCPV4_SERVER_ADDR_COUNT);
	if (net_dhcpv4_server_foreach_lease(s_ap, dhcp_lease_trace_cb, &c) != 0) {
		LOG_WRN("DHCP server: foreach_lease failed (server not running on s_ap?)");
		return;
	}
	if (c.slots == 0) {
		LOG_DBG("DHCP server: no active lease slots yet (no Discover seen or all FREE)");
	} else if (c.allocated == 0) {
		LOG_DBG("DHCP server: no ALLOCATED lease yet (Offer may be pending or TX failed)");
	}
}

static void dhcp_lease_dump_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);
	prov_log_dhcp_leases("~0.8s after Wi-Fi L2 join");
}

static void dhcp_lease_dump_work_fn_late(struct k_work *work)
{
	ARG_UNUSED(work);
	prov_log_dhcp_leases("~2.5s after Wi-Fi L2 join");
}

static K_WORK_DELAYABLE_DEFINE(s_dhcp_lease_dump_work, dhcp_lease_dump_work_fn);
static K_WORK_DELAYABLE_DEFINE(s_dhcp_lease_dump_work_late, dhcp_lease_dump_work_fn_late);

static void ap_events_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
			      struct net_if *iface)
{
	if (iface != s_ap) {
		return;
	}

	if (mgmt_event == NET_EVENT_WIFI_AP_STA_CONNECTED) {
		const struct wifi_ap_sta_info *sta = (const struct wifi_ap_sta_info *)cb->info;

		LOG_DBG("AP-STA joined: %02x:%02x:%02x:%02x:%02x:%02x",
			sta->mac[0], sta->mac[1], sta->mac[2],
			sta->mac[3], sta->mac[4], sta->mac[5]);
		LOG_DBG("DHCP server: Wi-Fi client associated (L2); waiting for Discover/Request on UDP/67");
		prov_log_dhcp_leases("immediately after L2 join");
		(void)k_work_reschedule(&s_dhcp_lease_dump_work, K_MSEC(800));
		(void)k_work_reschedule(&s_dhcp_lease_dump_work_late, K_MSEC(2500));
	} else if (mgmt_event == NET_EVENT_WIFI_AP_STA_DISCONNECTED) {
		const struct wifi_ap_sta_info *sta = (const struct wifi_ap_sta_info *)cb->info;

		LOG_DBG("AP-STA left: %02x:%02x:%02x:%02x:%02x:%02x",
			sta->mac[0], sta->mac[1], sta->mac[2],
			sta->mac[3], sta->mac[4], sta->mac[5]);
		LOG_DBG("DHCP server: Wi-Fi client disassociated (L2); lease may time out or clear on stop");
		(void)k_work_cancel_delayable(&s_dhcp_lease_dump_work);
		(void)k_work_cancel_delayable(&s_dhcp_lease_dump_work_late);
		prov_log_dhcp_leases("after STA left");
	} else if (mgmt_event == NET_EVENT_WIFI_AP_ENABLE_RESULT) {
		LOG_DBG("AP enable result event received");
	} else if (mgmt_event == NET_EVENT_WIFI_AP_DISABLE_RESULT) {
		LOG_DBG("AP disable result event received");
	}
}

static int s_listen_fd = -1;
static int s_tls_probe_fd = -1;
static atomic_t s_http_cfd = ATOMIC_INIT(-1);

#endif /* CONFIG_ESP_PROV_USE_SOFTAP -- SoftAP statics + ap_events_handler */

/* One transport per session: BLE vs SoftAP protocomm (not both concurrently).
 * Always defined: esp_prov_transport_choice() is part of the public API and the
 * transport-arbitration helpers stay compiled in single-transport builds (with
 * cross-transport teardown short-circuited under #if guards below).
 */
K_MUTEX_DEFINE(s_transport_mu);
static uint8_t s_transport_choice;

#if IS_ENABLED(CONFIG_ESP_PROV_USE_SOFTAP)

static atomic_t s_softap_abandoned;

static bool prov_http_dns_abort(void)
{
	return esp_prov_shared_stop_requested() || esp_prov_shared_is_finished() ||
	       (atomic_get(&s_softap_abandoned) != 0);
}

K_THREAD_STACK_DEFINE(http_thread_stack, CONFIG_ESP_PROV_HTTP_WORKER_STACK_SIZE);
static struct k_thread http_thread_data;

K_THREAD_STACK_DEFINE(dns_thread_stack, CONFIG_ESP_PROV_DNS_STACK_SIZE);
static struct k_thread dns_thread_data;
static atomic_t s_dns_fd = ATOMIC_INIT(-1);

static int enable_dhcp_and_ip(void)
{
	struct in_addr a;
	struct in_addr mask;

	if (net_addr_pton(AF_INET, CONFIG_ESP_PROV_SOFTAP_IPV4_GATEWAY, &a) ||
	    net_addr_pton(AF_INET, CONFIG_ESP_PROV_SOFTAP_IPV4_NETMASK, &mask)) {
		return -EINVAL;
	}

	net_if_ipv4_set_gw(s_ap, &a);

	if (net_if_ipv4_addr_add(s_ap, &a, NET_ADDR_MANUAL, 0) == NULL) {
		return -EIO;
	}

	if (!net_if_ipv4_set_netmask_by_addr(s_ap, &a, &mask)) {
		return -EIO;
	}

	if (net_addr_pton(AF_INET, CONFIG_ESP_PROV_SOFTAP_DHCP_POOL_BASE, &a) != 0) {
		return -EINVAL;
	}

	int dhcp_err = net_dhcpv4_server_start(s_ap, &a);

	if (dhcp_err != 0) {
		LOG_ERR("DHCP server start failed: %d", dhcp_err);
		return -EIO;
	}
#if defined(CONFIG_NET_DHCPV4_SERVER_OPTION_DNS_ADDRESS)
	if (CONFIG_NET_DHCPV4_SERVER_OPTION_DNS_ADDRESS[0] != '\0' &&
	    strcmp(CONFIG_NET_DHCPV4_SERVER_OPTION_DNS_ADDRESS, CONFIG_ESP_PROV_SOFTAP_IPV4_GATEWAY) != 0) {
		LOG_WRN("DHCP DNS option (%s) != SoftAP gateway (%s); captive DNS may not match AP IP",
			CONFIG_NET_DHCPV4_SERVER_OPTION_DNS_ADDRESS, CONFIG_ESP_PROV_SOFTAP_IPV4_GATEWAY);
	}
#endif
	LOG_INF("DHCP server started on SAP, base %s (pool size %u)",
		CONFIG_ESP_PROV_SOFTAP_DHCP_POOL_BASE,
		(unsigned int)CONFIG_NET_DHCPV4_SERVER_ADDR_COUNT);
#if IS_ENABLED(CONFIG_NET_DHCPV4_SERVER_OPTION_CAPTIVE_PORTAL)
	if (CONFIG_NET_DHCPV4_SERVER_OPTION_CAPTIVE_PORTAL_URI[0] != '\0') {
		LOG_DBG("DHCP Offer/ACK include opt114 (RFC8910): %s",
			CONFIG_NET_DHCPV4_SERVER_OPTION_CAPTIVE_PORTAL_URI);
	} else {
		LOG_DBG("DHCP Offer/ACK include opt114 (RFC8910): auto http://%s/generate_204",
			CONFIG_ESP_PROV_SOFTAP_IPV4_GATEWAY);
	}
#endif

	return 0;
}

/* After bind(): associate socket with the SoftAP iface. In APSTA, plain bind() can leave
 * TCP/UDP on the wrong iface; SO_BINDTODEVICE needs the *interface* name (e.g. wlan1), not
 * the devicetree label from dev->name (e.g. wifi_ap) -- that yields errno=ENOENT (2).
 */
static void prov_sock_bind_to_sap_iface(int fd)
{
	struct net_ifreq ifr;
	char ifname[NET_IFNAMSIZ];
	int nlen;

	if (s_ap == NULL || fd < 0) {
		return;
	}

	memset(&ifr, 0, sizeof(ifr));
	memset(ifname, 0, sizeof(ifname));

	nlen = net_if_get_name(s_ap, ifname, sizeof(ifname));
	if (nlen <= 0 || ifname[0] == '\0') {
#if IS_ENABLED(CONFIG_NET_INTERFACE_NAME)
		LOG_WRN("net_if_get_name(SAP) nlen=%d -- set CONFIG_NET_INTERFACE_NAME=y", nlen);
#else
		LOG_DBG("SO_BINDTODEVICE skipped (need CONFIG_NET_INTERFACE_NAME for iface name)");
#endif
		return;
	}

	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);

	if (zsock_setsockopt(fd, SOL_SOCKET, ZSOCK_SO_BINDTODEVICE, &ifr, sizeof(ifr)) != 0) {
		LOG_WRN("SO_BINDTODEVICE(%s) errno=%d", ifr.ifr_name, errno);
	} else {
		LOG_DBG("SO_BINDTODEVICE ok %s", ifr.ifr_name);
	}
}

static int wifi_ap_start(void)
{
	/* Same shape as samples/net/wifi/apsta_mode enable_ap_mode():
	 * open AP uses empty PSK string + WIFI_SECURITY_TYPE_NONE, not NULL psk. */
	static const uint8_t ap_psk_empty[] = "";

	struct wifi_connect_req_params ap = { 0 };

	ap.ssid = (const uint8_t *)ESP_PROV_SOFTAP_SSID;
	ap.ssid_length = strlen(ESP_PROV_SOFTAP_SSID);
	ap.psk = ap_psk_empty;
	ap.psk_length = 0U;
	ap.channel = WIFI_CHANNEL_ANY;
	ap.band = WIFI_FREQ_BAND_2_4_GHZ;
	ap.security = WIFI_SECURITY_TYPE_NONE;

	return net_mgmt(NET_REQUEST_WIFI_AP_ENABLE, s_ap, &ap, sizeof(ap));
}

static void wifi_ap_stop(void)
{
	(void)k_work_cancel_delayable(&s_dhcp_lease_dump_work);
	(void)k_work_cancel_delayable(&s_dhcp_lease_dump_work_late);
	(void)net_dhcpv4_server_stop(s_ap);
	(void)net_mgmt(NET_REQUEST_WIFI_AP_DISABLE, s_ap, NULL, 0);
}

/* Unblock prov-http / prov-dns: shutdown active client + listeners (idempotent). Thread
 * context only -- ISR callers must use esp_prov_cancel_isr() (no zsock_* from ISR).
 *
 * On ESP32 Wi-Fi offload, zsock_shutdown() alone may not wake a blocked zsock_recv() on
 * the accepted client quickly; zsock_close() after a CAS is required so cancel/timeout
 * reliably tears down (see journal).
 */
static void prov_shutdown_http_client_socket(void)
{
	int cfd = atomic_get(&s_http_cfd);

	if (cfd < 0) {
		return;
	}

	(void)zsock_shutdown(cfd, ZSOCK_SHUT_RDWR);
	if (atomic_cas(&s_http_cfd, (atomic_val_t)cfd, (atomic_val_t)-1)) {
		(void)zsock_close(cfd);
	}
}

/* Like the HTTP client fd: on ESP32 Wi-Fi offload, shutdown alone may not release the
 * UDP port; close is required so a later provisioning session can bind :53 again.
 * Only one of prov-dns or teardown may close -- atomic_cas matches prov_shutdown_http_client_socket.
 */
static void prov_shutdown_dns_socket(void)
{
	int fd = (int)atomic_get(&s_dns_fd);

	if (fd < 0) {
		return;
	}
	(void)zsock_shutdown(fd, ZSOCK_SHUT_RDWR);
	if (atomic_cas(&s_dns_fd, (atomic_val_t)fd, (atomic_val_t)-1)) {
		(void)zsock_close(fd);
	}
}

static void prov_shutdown_prov_sockets(void)
{
	prov_shutdown_http_client_socket();
	if (s_listen_fd >= 0) {
		(void)zsock_shutdown(s_listen_fd, ZSOCK_SHUT_RDWR);
	}
	if (s_tls_probe_fd >= 0) {
		(void)zsock_shutdown(s_tls_probe_fd, ZSOCK_SHUT_RDWR);
	}
	prov_shutdown_dns_socket();
}

static void softap_shutdown_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);

	prov_shutdown_prov_sockets();
	/*
	 * BLE-wins teardown: join prov-http and prov-dns so their stack-resident HTTP
	 * scratch (~13.5 KiB on prov-http) is reclaimed before the BLE protocomm path
	 * consumes deep mbedTLS stacks. Both threads see s_softap_abandoned via
	 * prov_http_dns_abort() and exit promptly after the sockets above are shut.
	 * The joins are idempotent: routine teardown re-joins and gets 0 immediately
	 * if the threads are already finished.
	 *
	 * Do not wifi_ap_stop() here: BLE /prov-scan must use SAP net_if; tearing AP
	 * down mid-session then scanning on STA faulted the esp32 driver (PC 0).
	 * AP + DHCP stay up until esp_prov_routine_run() teardown.
	 */
	(void)k_thread_join(&http_thread_data, K_SECONDS(10));
	(void)k_thread_join(&dns_thread_data, K_SECONDS(5));
}

K_WORK_DEFINE(softap_shutdown_work, softap_shutdown_work_fn);

#endif /* CONFIG_ESP_PROV_USE_SOFTAP -- IP/DHCP, sockets, AP teardown work */

#if IS_ENABLED(CONFIG_ESP_PROV_USE_BLE)
static void ble_stop_only_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);

	esp_prov_ble_stop();
}

K_WORK_DEFINE(ble_stop_only_work, ble_stop_only_work_fn);
#endif /* CONFIG_ESP_PROV_USE_BLE */

bool esp_prov_try_select_ble(void)
{
#if !IS_ENABLED(CONFIG_ESP_PROV_USE_BLE)
	/* BLE transport not built: nothing to select. */
	return false;
#else
	k_mutex_lock(&s_transport_mu, K_FOREVER);
	if (s_transport_choice == ESP_PROV_TP_SOFTAP) {
		k_mutex_unlock(&s_transport_mu);
		return false;
	}
	if (s_transport_choice == ESP_PROV_TP_NONE) {
		s_transport_choice = ESP_PROV_TP_BLE;
		k_mutex_unlock(&s_transport_mu);
#if IS_ENABLED(CONFIG_ESP_PROV_USE_SOFTAP)
		atomic_set(&s_softap_abandoned, 1);
		LOG_INF("Provisioning: BLE transport selected -- stopping SoftAP HTTP/DNS "
			"(AP left up for scan; full AP stop at session end)");
		(void)k_work_submit(&softap_shutdown_work);
#else
		LOG_INF("Provisioning: BLE transport selected (SoftAP not built)");
#endif
		return true;
	}
	k_mutex_unlock(&s_transport_mu);
	return true;
#endif
}

void esp_prov_try_select_softap(void)
{
#if !IS_ENABLED(CONFIG_ESP_PROV_USE_SOFTAP)
	/* SoftAP transport not built: nothing to select. */
	return;
#else
	k_mutex_lock(&s_transport_mu, K_FOREVER);
	if (s_transport_choice == ESP_PROV_TP_BLE) {
		k_mutex_unlock(&s_transport_mu);
		return;
	}
	if (s_transport_choice == ESP_PROV_TP_NONE) {
		s_transport_choice = ESP_PROV_TP_SOFTAP;
		k_mutex_unlock(&s_transport_mu);
#if IS_ENABLED(CONFIG_ESP_PROV_USE_BLE)
		LOG_INF("Provisioning: SoftAP transport selected -- stopping BLE provisioning");
		(void)k_work_submit(&ble_stop_only_work);
#else
		LOG_INF("Provisioning: SoftAP transport selected (BLE not built)");
#endif
		return;
	}
	k_mutex_unlock(&s_transport_mu);
#endif
}

int esp_prov_transport_choice(void)
{
	int c;

	k_mutex_lock(&s_transport_mu, K_FOREVER);
	c = (int)s_transport_choice;
	k_mutex_unlock(&s_transport_mu);
	return c;
}

#if IS_ENABLED(CONFIG_ESP_PROV_USE_SOFTAP)

static int read_http_headers(int fd, char *buf, size_t cap, size_t *out_len)
{
	size_t n = 0U;

	while (n + 4U < cap) {
		if (prov_http_dns_abort()) {
			return -ECONNRESET;
		}

		size_t room = cap - n - 1U;
		size_t chunk = MIN(room, 256U);
		int r = zsock_recv(fd, buf + n, chunk, 0);

		if (r < 0) {
			int e = errno;

			/* SO_RCVTIMEO: wake periodically so cancellation can unblock this thread. */
			if (e == EAGAIN || e == EWOULDBLOCK
#if defined(ETIMEDOUT)
			    || e == ETIMEDOUT
#endif
			) {
				if (prov_http_dns_abort()) {
					return -ECONNRESET;
				}
				/* If SO_RCVTIMEO is ignored and recv returns immediately, avoid starving
				 * the main thread with a tight loop.
				 */
				k_msleep(1);
				continue;
			}
			return -e;
		}
		if (r == 0) {
			return -ECONNRESET;
		}
		n += (size_t)r;
		buf[n] = '\0';
		if (strstr(buf, "\r\n\r\n") != NULL) {
			break;
		}
	}
	*out_len = n;
	return 0;
}

static int header_content_length(const char *hdr, int *clen_out)
{
	const char *lim = strstr(hdr, "\r\n\r\n");
	static const char clname[] = "content-length:";

	if (lim == NULL) {
		return -1;
	}

	*clen_out = -1;
	for (const char *line = hdr; line < lim;) {
		const char *eol = strstr(line, "\r\n");

		if (eol == NULL || eol > lim) {
			break;
		}
		size_t i;

		for (i = 0; i < sizeof(clname) - 1U && line + i < eol; i++) {
			char c = line[i];

			if (c >= 'A' && c <= 'Z') {
				c = (char)(c + 32);
			}
			if (c != clname[i]) {
				break;
			}
		}
		if (i == sizeof(clname) - 1U) {
			const char *p = line + sizeof(clname) - 1U;

			while (p < eol && (*p == ' ' || *p == '\t')) {
				p++;
			}
			*clen_out = atoi(p);
			return 0;
		}
		line = eol + 2;
	}
	return 0;
}

static int header_name_eq(const char *line, const char *eol, const char *name_lc_colon)
{
	const char *p = line;

	while (p < eol && (*p == ' ' || *p == '\t')) {
		p++;
	}
	for (size_t i = 0; name_lc_colon[i] != '\0'; i++) {
		if (p + i >= eol) {
			return 0;
		}
		char c = p[i];

		if (c >= 'A' && c <= 'Z') {
			c = (char)(c + 32);
		}
		if (c != name_lc_colon[i]) {
			return 0;
		}
	}
	return 1;
}

static int header_cookie_session(const char *hdr, uint32_t *sid_out)
{
	const char *lim = strstr(hdr, "\r\n\r\n");

	if (lim == NULL) {
		return -1;
	}

	*sid_out = 0U;
	for (const char *line = hdr; line < lim;) {
		const char *eol = strstr(line, "\r\n");

		if (eol == NULL || eol > lim) {
			break;
		}
		if (header_name_eq(line, eol, "cookie:")) {
			const char *s = strstr(line, "session=");

			if (s != NULL && s < eol) {
				s += 8;
				*sid_out = (uint32_t)strtoul(s, NULL, 10);
				return 1;
			}
		}
		line = eol + 2;
	}
	return 0;
}

static int recv_body(int fd, uint8_t *body, size_t want)
{
	size_t n = 0U;

	while (n < want) {
		if (prov_http_dns_abort()) {
			return -ECONNRESET;
		}

		int r = zsock_recv(fd, body + n, want - n, 0);

		if (r < 0) {
			int e = errno;

			if (e == EAGAIN || e == EWOULDBLOCK
#if defined(ETIMEDOUT)
			    || e == ETIMEDOUT
#endif
			) {
				if (prov_http_dns_abort()) {
					return -ECONNRESET;
				}
				k_msleep(1);
				continue;
			}
			return -e;
		}
		if (r == 0) {
			return -ECONNRESET;
		}
		n += (size_t)r;
	}
	return 0;
}

static bool send_all(int fd, const void *data, size_t len)
{
	const uint8_t *p = data;
	size_t n = 0U;

	while (n < len) {
		if (prov_http_dns_abort()) {
			return false;
		}

		int s = zsock_send(fd, p + n, len - n, 0);

		if (s < 0) {
			int e = errno;

			if (e == EAGAIN || e == EWOULDBLOCK
#if defined(ETIMEDOUT)
			    || e == ETIMEDOUT
#endif
			) {
				if (prov_http_dns_abort()) {
					return false;
				}
				k_msleep(1);
				continue;
			}
			LOG_WRN("HTTP send failed: errno=%d sent=%zu/%zu", e, n, len);
			return false;
		}
		if (s == 0) {
			LOG_WRN("HTTP send: 0 (peer closed?) sent=%zu/%zu", n, len);
			return false;
		}
		n += (size_t)s;
	}
	return true;
}

static bool respond_bin(int fd, const void *body, size_t blen, bool set_cookie, bool connection_close)
{
	char head[192];

#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE) || IS_ENABLED(CONFIG_ESP_PROV_PKT_LOG) ||                \
	IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)
	char wdesc[80];

	snprintf(wdesc, sizeof(wdesc), "http TX 200 octet-stream cookie=%d", set_cookie ? 1 : 0);
	esp_prov_trace_app(wdesc, "TX", body, blen);
#endif

	LOG_DBG("HTTP TX 200 octet-stream body_len=%zu set_cookie=%c sid=%" PRIu32 "%s", blen,
		set_cookie ? 'Y' : 'N', set_cookie ? s_cookie_id : 0U,
		connection_close ? " Connection: close" : "");
#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE)
	http_log_hex("TX body preview", body, blen);
#endif

	/* Optional Connection: close after proto-ver: single-thread server must return to
	 * accept() before a second TCP for /prov-session is unblocked (see Kconfig). */
	if (set_cookie) {
		snprintf(head, sizeof(head),
			 "HTTP/1.0 200 OK\r\n"
			 "Content-Type: application/octet-stream\r\n"
			 "Content-Length: %zu\r\n"
			 "Set-Cookie: session=%" PRIu32 "\r\n"
			 "%s"
			 "\r\n",
			 blen, s_cookie_id,
			 connection_close ? "Connection: close\r\n" : "");
	} else {
		snprintf(head, sizeof(head),
			 "HTTP/1.0 200 OK\r\n"
			 "Content-Type: application/octet-stream\r\n"
			 "Content-Length: %zu\r\n"
			 "%s"
			 "\r\n",
			 blen, connection_close ? "Connection: close\r\n" : "");
	}
	if (!send_all(fd, head, strlen(head)) || !send_all(fd, body, blen)) {
		LOG_WRN("HTTP TX 200 aborted (incomplete send)");
		return false;
	}
	return true;
}

static void respond_404(int fd)
{
	static const char *t = "HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE) || IS_ENABLED(CONFIG_ESP_PROV_PKT_LOG) ||                \
	IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)
	esp_prov_trace_app("http TX 404", "TX", NULL, 0);
#endif
	LOG_WRN("HTTP TX 404 Not Found");
	(void)send_all(fd, t, strlen(t));
}

static bool parse_request_line(const char *hdr, char *method, size_t mlen, char *path, size_t plen)
{
	const char *eol = strstr(hdr, "\r\n");

	if (eol == NULL) {
		return false;
	}
	if (sscanf(hdr, "%7s %63s", method, path) != 2) {
		return false;
	}
	(void)mlen;
	(void)eol;

	/* Some HTTP clients send absolute-form targets, e.g.
	 * "GET http://192.168.4.1/proto-ver?transport=softap HTTP/1.1" */
	if (path[0] != '/' && path[0] != '\0') {
		const char *auth = strstr(path, "://");

		if (auth != NULL) {
			const char *slash = strchr(auth + 3, '/');

			if (slash != NULL) {
				/* Copy via tmp: slash points into path[]; GCC -Wstringop-overread
				 * flags overlapping memmove when plen is 64 and sscanf used %63s. */
				char tmp[64];
				size_t i = 0U;

				while (slash[i] != '\0' && i + 1U < sizeof(tmp)) {
					tmp[i] = slash[i];
					i++;
				}
				tmp[i] = '\0';
				if (i + 1U >= plen) {
					memcpy(path, tmp, plen - 1U);
					path[plen - 1U] = '\0';
				} else {
					memcpy(path, tmp, i + 1U);
				}
			}
		}
	}
	return path[0] == '/';
}

/* Path from request line may include ?query (SoftAP app); Rust classifies with substring. */
static bool path_matches(const char *path, const char *ep)
{
	if (path == NULL || path[0] != '/') {
		return false;
	}
	const char *p = path + 1;

	for (size_t i = 0;; i++) {
		if (ep[i] == '\0') {
			return p[i] == '\0' || p[i] == '?';
		}
		if (p[i] != ep[i]) {
			return false;
		}
	}
}

/** True for "/" or "/?query" -- some OSes probe the gateway root before /generate_204. */
static bool path_is_captive_root(const char *path)
{
	if (path == NULL || path[0] != '/') {
		return false;
	}
	return path[1] == '\0' || path[1] == '?';
}

static bool ensure_session(int fd, const char *hdr, bool *set_cookie_out,
			   bool first_sec_request_on_connection)
{
	uint32_t cookie_sid = 0U;
	int cr = header_cookie_session(hdr, &cookie_sid);
	bool same = false;
	esp_prov_sec1_t *sec = esp_prov_sec1_http();

	(void)fd;
	*set_cookie_out = false;

	/* First POST on a *new* TCP: match cookie to prior connection, or start fresh.
	 * Later POSTs on the *same* TCP (keep-alive, no Cookie): keep sec1 -- matches
	 * Rust wifi_ap.rs and avoids resetting crypto after /prov-session. */
	if (!first_sec_request_on_connection) {
		same = true;
	} else if (cr == 1 && s_have_cookie && cookie_sid == s_cookie_id) {
		same = true;
	}

	if (!same) {
		uint32_t prev_sid = s_cookie_id;

		if (s_have_cookie) {
			LOG_DBG("HTTP sec1: closing transport sid=%" PRIu32, prev_sid);
			(void)esp_prov_sec1_transport_close(sec, prev_sid);
		}
		do {
			s_cookie_id = sys_rand32_get();
		} while (s_cookie_id == 0U);

		LOG_DBG("HTTP sec1: transport_open sid=%" PRIu32 " (Set-Cookie on response)", s_cookie_id);
		if (esp_prov_sec1_transport_open(sec, s_cookie_id) != 0) {
			LOG_WRN("HTTP sec1: transport_open failed");
			return false;
		}
		s_have_cookie = true;
		*set_cookie_out = true;
	} else if (first_sec_request_on_connection) {
		LOG_DBG("HTTP sec1: reuse sid=%" PRIu32 " (Cookie on new TCP)", s_cookie_id);
	}
	return true;
}

/* Decode first question name (offset 12) for logs; best-effort, truncated if long. */
static void dns_qname_log_str(const uint8_t *rx, int len, char *out, size_t out_sz)
{
	size_t o = 0U;
	int pos = 12;

	out[0] = '\0';
	if (len < 13) {
		return;
	}
	while (pos < len) {
		uint8_t lbl = rx[pos];

		if (lbl == 0U) {
			break;
		}
		if ((lbl & 0xC0U) == 0xC0U) {
			(void)snprintf(out, out_sz, "(ptr)");
			return;
		}
		pos++;
		if (pos + (int)lbl > len) {
			break;
		}
		if (o > 0U && o + 1U < out_sz) {
			out[o++] = '.';
		}
		for (uint8_t i = 0U; i < lbl && o + 1U < out_sz; i++) {
			out[o++] = (char)rx[pos++];
		}
	}
	if (o < out_sz) {
		out[o] = '\0';
	} else {
		out[out_sz - 1U] = '\0';
	}
}

static void dns_server_thread(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	int fd = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (fd < 0) {
		LOG_WRN("DNS: socket failed");
		return;
	}

	struct sockaddr_in sin = { 0 };

	sin.sin_family = AF_INET;
	sin.sin_port = htons(53);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);

	if (zsock_bind(fd, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
		LOG_WRN("DNS: bind :53 failed");
		zsock_close(fd);
		return;
	}

	prov_sock_bind_to_sap_iface(fd);

	struct zsock_timeval tv = { .tv_sec = 0, .tv_usec = 500000 };

	zsock_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	atomic_set(&s_dns_fd, (atomic_val_t)fd);

	LOG_INF("DNS server on :53 (all queries -> %s)", CONFIG_ESP_PROV_SOFTAP_IPV4_GATEWAY);

	struct in_addr gw;

	(void)net_addr_pton(AF_INET, CONFIG_ESP_PROV_SOFTAP_IPV4_GATEWAY, &gw);

	uint8_t rx[512];
	uint8_t tx[512];

	while (!prov_http_dns_abort()) {
		struct sockaddr_in from = { 0 };
		socklen_t fromlen = sizeof(from);
		int len = zsock_recvfrom(fd, rx, sizeof(rx), 0,
					 (struct sockaddr *)&from, &fromlen);

		if (len <= 0) {
			continue;
		}
#if IS_ENABLED(CONFIG_ESP_PROV_SOFTAP_NET_HEX)
		prov_net_hexdump("DNS UDP RX", rx, (size_t)len);
#endif
		if (len < 12) {
			continue;
		}

		/* Walk the question section to find its end. */
		int pos = 12;

		while (pos < len) {
			uint8_t lbl = rx[pos];

			if (lbl == 0U) {
				pos++;
				break;
			}
			if ((lbl & 0xC0) == 0xC0) {
				pos += 2;
				break;
			}
			pos += lbl + 1;
		}
		if (pos + 4 > len) {
			continue;
		}
		uint16_t qtype = ((uint16_t)rx[pos] << 8) | rx[pos + 1];

		pos += 4; /* skip QTYPE + QCLASS */

		int q_end = pos;

		/* Build response. */
		int w = 0;

		memcpy(tx, rx, 2);  /* txid */
		w = 2;
		tx[w++] = 0x81;     /* QR=1, RD=1 */
		tx[w++] = 0x80;     /* RA=1 */
		tx[w++] = 0x00;
		tx[w++] = 0x01;     /* QDCOUNT=1 */
		bool add_a = (qtype == 1U);

		tx[w++] = 0x00;
		tx[w++] = add_a ? 0x01 : 0x00; /* ANCOUNT */
		tx[w++] = 0x00;
		tx[w++] = 0x00;     /* NSCOUNT */
		tx[w++] = 0x00;
		tx[w++] = 0x00;     /* ARCOUNT */

		int qlen = q_end - 12;

		if (w + qlen + 16 > (int)sizeof(tx)) {
			continue;
		}
		memcpy(tx + w, rx + 12, qlen);
		w += qlen;

		if (add_a) {
			tx[w++] = 0xC0;
			tx[w++] = 0x0C; /* name pointer -> offset 12 */
			tx[w++] = 0x00;
			tx[w++] = 0x01; /* type A */
			tx[w++] = 0x00;
			tx[w++] = 0x01; /* class IN */
			tx[w++] = 0x00;
			tx[w++] = 0x00;
			tx[w++] = 0x00;
			tx[w++] = 0x00; /* TTL 0 */
			tx[w++] = 0x00;
			tx[w++] = 0x04; /* RDLEN 4 */
			memcpy(tx + w, &gw.s_addr, 4);
			w += 4;
		}

		char dcli[NET_IPV4_ADDR_LEN];
		char qn[96];

		dns_qname_log_str(rx, len, qn, sizeof(qn));
		(void)net_addr_ntop(AF_INET, &from.sin_addr, dcli, sizeof(dcli));
		/* Visible at INF: confirms phone is using us as DNS -- Android sends
		 * connectivitycheck.gstatic.com / clients3.google.com / etc. before HTTP
		 * captive probe. If this never appears, the phone never picked up our
		 * DHCP DNS option (CONFIG_NET_DHCPV4_SERVER_OPTION_DNS_ADDRESS).
		 */
		LOG_DBG("DNS RX from %s len=%d qtype=%u qname=%s %s", dcli, len, (unsigned int)qtype, qn,
			add_a ? "-> A " CONFIG_ESP_PROV_SOFTAP_IPV4_GATEWAY : "-> empty (not A)");

#if IS_ENABLED(CONFIG_ESP_PROV_SOFTAP_NET_HEX)
		prov_net_hexdump("DNS UDP TX", tx, (size_t)w);
#endif
		if (zsock_sendto(fd, tx, w, 0, (struct sockaddr *)&from, fromlen) < 0) {
			LOG_WRN("DNS: sendto failed");
		}
	}

	prov_shutdown_dns_socket();
}

static bool http_req_is_provisioning(const char *method, const char *path)
{
	if (strcmp(method, "GET") == 0 && path_matches(path, "proto-ver")) {
		return true;
	}
	if (strcmp(method, "POST") == 0) {
		if (path_matches(path, "proto-ver") || path_matches(path, "prov-session") ||
		    path_matches(path, "prov-config") || path_matches(path, "prov-scan")) {
			return true;
		}
	}
	return false;
}

static void http_handle_client(int cfd)
{
	char hdr[HTTP_HDR_MAX + 1];
	uint8_t body[HTTP_BODY_MAX];
	uint8_t resp[HTTP_HDR_MAX + HTTP_BODY_MAX];
	const size_t hdr_cap = sizeof(hdr);
	const size_t body_cap = sizeof(body);
	const size_t resp_cap = sizeof(resp);
	esp_prov_sec1_t *sec = esp_prov_sec1_http();
	bool first_sec_ensure = true;
	bool logged_first_hdr_fail = false;
#if IS_ENABLED(CONFIG_ESP_PROV_HTTP_CLOSE_AFTER_PROTO_VER)
	/* After Connection: close on /proto-ver, the client closes the TCP; next read is EOF (-ECONNRESET), not an error. */
	bool expect_peer_close_next_hdr = false;
#endif
	unsigned int req_num = 0U;
	unsigned int http_req_count = 0U;

	for (;;) {
		size_t hn = 0U;
		bool end_tcp_after_captive = false;

		if (prov_http_dns_abort()) {
			break;
		}

		int hret = read_http_headers(cfd, hdr, hdr_cap - 1U, &hn);

		if (hret != 0) {
#if IS_ENABLED(CONFIG_ESP_PROV_HTTP_CLOSE_AFTER_PROTO_VER)
			if (expect_peer_close_next_hdr && hret == -ECONNRESET &&
			    !esp_prov_shared_stop_requested()) {
				LOG_DBG("HTTP: peer closed TCP after /proto-ver (Connection: close -- expected)");
				expect_peer_close_next_hdr = false;
				break;
			}
			expect_peer_close_next_hdr = false;
#endif
			if (esp_prov_shared_stop_requested() && hret == -ECONNRESET) {
				LOG_DBG("HTTP: header read aborted (provisioning cancel)");
			} else {
				LOG_WRN("HTTP: header read end/err ret=%d%s", hret,
					(hret == -ECONNRESET) ? " (EOF/peer close)" : "");
			}
			if (hret < 0 && hret != -ECONNRESET) {
				LOG_WRN("HTTP: errno=%d", -hret);
			}
			if (!logged_first_hdr_fail) {
				esp_prov_trace_note("http: header read failed (no response)");
				logged_first_hdr_fail = true;
			}
			break;
		}
#if IS_ENABLED(CONFIG_ESP_PROV_HTTP_CLOSE_AFTER_PROTO_VER)
		expect_peer_close_next_hdr = false;
#endif
		hdr[hn] = '\0';

		char method[8];
		char path[64];

		if (!parse_request_line(hdr, method, sizeof(method), path, sizeof(path))) {
			char peek[96];
			size_t pl = strcspn(hdr, "\r\n");

			if (pl >= sizeof(peek)) {
				pl = sizeof(peek) - 1U;
			}
			memcpy(peek, hdr, pl);
			peek[pl] = '\0';
			LOG_WRN("HTTP: bad request line (first line): \"%s\"", peek);
			esp_prov_trace_note("http: bad request line (no response)");
			break;
		}

		req_num++;
		http_req_count = req_num;

		int clen = 0;

		(void)header_content_length(hdr, &clen);
		if (clen < 0) {
			clen = 0;
		}

		uint32_t ck_sid = 0U;
		int ck = header_cookie_session(hdr, &ck_sid);

		LOG_DBG("HTTP #%u: %s %s hdr_bytes=%zu clen=%d cookie=%s sid=%" PRIu32, req_num, method,
			path, hn, clen, ck == 1 ? "yes" : (ck == 0 ? "no" : "?"),
			ck == 1 ? ck_sid : 0U);

		if (http_req_is_provisioning(method, path)) {
			esp_prov_try_select_softap();
		}

		/* Android / iOS / Windows connectivity probes: respond 204 so the OS
		 * keeps traffic routed through our SoftAP instead of falling back to
		 * cellular.  Must be checked before the proto-ver GET handler.
		 *
		 * Use HTTP/1.0 + Content-Length: 0 (Rust wifi_ap parity). HTTP/1.1 with
		 * Connection: close confused some Android builds (captive check flaps ->
		 * "no internet" / cellular bypass). HTTP/1.0 implies close after response
		 * without extra headers.
		 */
		if (strcmp(method, "GET") == 0) {
			static const char r204_captive[] =
				"HTTP/1.0 204 No Content\r\n"
				"Content-Length: 0\r\n\r\n";

			static const char *const captive_paths[] = {
				"generate_204", "gen_204", "hotspot-detect", "ncsi.txt",
				"canonical.html", "redirect",
				/* Substrings on path (Host header may carry the FQDN). */
				"connectivitycheck", "gstatic", "msftconnecttest",
				"connecttest", "success.txt", "captiveportal", "networkcheck",
				NULL,
			};

			if (path_is_captive_root(path)) {
				/* Debug-only: confirms we replied 204 to a phone's
				 * connectivity probe (Android / iOS / Windows). Without this
				 * the OS shows "no internet" or falls back to cellular and the
				 * Espressif app can't open /proto-ver.
				 */
				LOG_DBG("HTTP TX 204 captive (root probe GET /)");
				if (!send_all(cfd, r204_captive, sizeof(r204_captive) - 1)) {
					LOG_WRN("HTTP TX 204 captive root: send failed");
				}
				end_tcp_after_captive = true;
			} else {
				for (int i = 0; captive_paths[i] != NULL; i++) {
					if (strstr(path, captive_paths[i]) != NULL) {
						LOG_DBG("HTTP TX 204 captive (path=%s)", path);
						if (!send_all(cfd, r204_captive, sizeof(r204_captive) - 1)) {
							LOG_WRN("HTTP TX 204 captive: send failed");
						}
						end_tcp_after_captive = true;
						break;
					}
				}
			}
		}

		if (end_tcp_after_captive) {
			/* Single-thread HTTP: return to accept(). Otherwise we stay in
			 * read_http_headers() on this idle captive socket while the Espressif app
			 * opens another TCP for /proto-ver (second SYN sits in listen backlog).
			 */
			LOG_DBG("HTTP: end captive TCP -- accept loop can take protocomm client");
			break;
		}

		if (strcmp(method, "GET") == 0 && path_matches(path, "proto-ver")) {
			/* Visible at INF: this is the milestone where the Espressif app
			 * has finished its connectivity check and started protocomm. After
			 * this, the SoftAP transport is auto-selected and BLE is stopped.
			 */
			LOG_INF("HTTP RX GET /proto-ver (Espressif app reached protocomm)");
#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE) || IS_ENABLED(CONFIG_ESP_PROV_PKT_LOG) ||                \
	IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)
			esp_prov_trace_app("http RX GET /proto-ver", "RX", NULL, 0);
#endif
			/* Same as Rust send_ok / protocomm HTTP: octet-stream, not application/json. */
#if IS_ENABLED(CONFIG_ESP_PROV_HTTP_CLOSE_AFTER_PROTO_VER)
			respond_bin(cfd, ESP_PROV_JSON_PROTO_VER, strlen(ESP_PROV_JSON_PROTO_VER), false, true);
			expect_peer_close_next_hdr = true;
#else
			respond_bin(cfd, ESP_PROV_JSON_PROTO_VER, strlen(ESP_PROV_JSON_PROTO_VER), false, false);
#endif
			goto next_req;
		}

		if (strcmp(method, "POST") != 0) {
			respond_404(cfd);
			goto next_req;
		}

		if ((size_t)clen > body_cap) {
			LOG_WRN("HTTP #%u: Content-Length %d too large (max %zu) -- no response", req_num, clen,
				body_cap);
			esp_prov_trace_note("http: invalid Content-Length (no response)");
			break;
		}

		const char *hend = strstr(hdr, "\r\n\r\n");
		size_t already = 0U;

		if (hend != NULL) {
			const char *bstart = hend + 4;

			already = hn - (size_t)(bstart - hdr);
			if (already > (size_t)clen) {
				already = (size_t)clen;
			}
			memcpy(body, bstart, already);
		}

		if ((size_t)clen > already) {
			if (recv_body(cfd, body + already, (size_t)clen - already) != 0) {
				LOG_WRN("HTTP #%u: body recv failed (need %zu more bytes)", req_num,
					(size_t)clen - already);
				esp_prov_trace_note("http: body recv failed (no response)");
				break;
			}
		}

		if (clen > 0) {
#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE)
			http_log_hex("RX POST body", body, (size_t)clen);
#endif
		}

		if (path_matches(path, "proto-ver")) {
#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE) || IS_ENABLED(CONFIG_ESP_PROV_PKT_LOG) ||                \
	IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)
			esp_prov_trace_app("http RX POST /proto-ver", "RX", body, (size_t)clen);
#endif
#if IS_ENABLED(CONFIG_ESP_PROV_HTTP_CLOSE_AFTER_PROTO_VER)
			respond_bin(cfd, ESP_PROV_JSON_PROTO_VER, strlen(ESP_PROV_JSON_PROTO_VER), false, true);
			expect_peer_close_next_hdr = true;
			LOG_DBG("HTTP #%u: POST /proto-ver done -- Connection: close; next /prov-session on new TCP",
				req_num);
#else
			respond_bin(cfd, ESP_PROV_JSON_PROTO_VER, strlen(ESP_PROV_JSON_PROTO_VER), false, false);
			LOG_DBG("HTTP #%u: POST /proto-ver done -- same TCP open, blocking for next request "
				"(e.g. /prov-session; quiet here is normal)",
				req_num);
#endif
			goto next_req;
		}

		bool set_ck = false;

		if (!ensure_session(cfd, hdr, &set_ck, first_sec_ensure)) {
			LOG_WRN("HTTP #%u: ensure_session failed -- no response sent", req_num);
			esp_prov_trace_note("http: ensure_session failed (no response)");
			break;
		}
		first_sec_ensure = false;

		size_t rlen = 0U;
		int err = -1;

		if (path_matches(path, "prov-session")) {
			static const uint8_t session_sec0[] = { 0x10, 0x00, 0x52, 0x00 };

#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE) || IS_ENABLED(CONFIG_ESP_PROV_PKT_LOG) ||                \
	IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)
			esp_prov_trace_app("http RX POST /prov-session", "RX", body, (size_t)clen);
#endif
			err = esp_prov_sec1_process_session(sec, body, (size_t)clen, ESP_PROV_DEFAULT_POP,
							    resp, resp_cap, &rlen);
			if (err == 0) {
				LOG_DBG("HTTP #%u prov-session: sec1 OK -> resp_len=%zu", req_num, rlen);
				respond_bin(cfd, resp, rlen, set_ck, false);
			} else {
				/* Rust/ESP app: Sec0 fallback so client can retry (same as BLE path). */
				LOG_WRN("HTTP #%u prov-session: sec1_process err=%d -> Sec0 fallback", req_num,
					err);
				esp_prov_trace_note("http: prov-session sec1 error -> Sec0 fallback");
				respond_bin(cfd, session_sec0, sizeof(session_sec0), set_ck, false);
			}
		} else if (path_matches(path, "prov-config")) {
			uint8_t work[HTTP_BODY_MAX];
			bool finished = false;

			if (!esp_prov_sec1_is_ready(sec)) {
				LOG_WRN("HTTP #%u prov-config: sec1 not ready -- no response", req_num);
				esp_prov_trace_note("http: prov-config before session ready (no response)");
				break;
			}
			if ((size_t)clen > sizeof(work)) {
				LOG_WRN("HTTP #%u prov-config: body too large", req_num);
				esp_prov_trace_note("http: prov-config body too large (no response)");
				break;
			}
#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE) || IS_ENABLED(CONFIG_ESP_PROV_PKT_LOG) ||                \
	IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)
			esp_prov_trace_app("http RX POST /prov-config", "RX", body, (size_t)clen);
#endif
			memcpy(work, body, (size_t)clen);
			if (esp_prov_sec1_apply(sec, work, (size_t)clen) != 0) {
				LOG_WRN("HTTP #%u prov-config: sec1_apply(decrypt) failed", req_num);
				esp_prov_trace_note("http: prov-config decrypt/apply failed (no response)");
				break;
			}
			err = esp_prov_shared_dispatch_config(sec, work, (size_t)clen, resp, resp_cap,
							      &rlen, &finished);
			if (err == 0 && esp_prov_sec1_apply(sec, resp, rlen) != 0) {
				err = -1;
			}
			if (err == 0) {
				LOG_DBG("HTTP #%u prov-config: dispatch OK finished=%d resp_len=%zu", req_num,
					finished ? 1 : 0, rlen);
				(void)respond_bin(cfd, resp, rlen, set_ck, false);
				if (finished) {
					esp_prov_shared_signal_finished();
				}
			} else {
				LOG_WRN("HTTP #%u prov-config: dispatch failed -- no response", req_num);
				esp_prov_trace_note("http: prov-config dispatch failed (no response)");
			}
		} else if (path_matches(path, "prov-scan")) {
			uint8_t work[HTTP_BODY_MAX];

			if (!esp_prov_sec1_is_ready(sec)) {
				LOG_WRN("HTTP #%u prov-scan: sec1 not ready -- no response", req_num);
				esp_prov_trace_note("http: prov-scan before session ready (no response)");
				break;
			}
			if ((size_t)clen > sizeof(work)) {
				LOG_WRN("HTTP #%u prov-scan: body too large", req_num);
				esp_prov_trace_note("http: prov-scan body too large (no response)");
				break;
			}
#if IS_ENABLED(CONFIG_ESP_PROV_APP_TRACE) || IS_ENABLED(CONFIG_ESP_PROV_PKT_LOG) ||                \
	IS_ENABLED(CONFIG_ESP_PROV_CONSOLE_PROBE)
			esp_prov_trace_app("http RX POST /prov-scan", "RX", body, (size_t)clen);
#endif
			memcpy(work, body, (size_t)clen);
			if (esp_prov_sec1_apply(sec, work, (size_t)clen) != 0) {
				LOG_WRN("HTTP #%u prov-scan: sec1_apply(decrypt) failed", req_num);
				esp_prov_trace_note("http: prov-scan decrypt/apply failed (no response)");
				break;
			}
			err = esp_prov_shared_dispatch_scan(sec, work, (size_t)clen, resp, resp_cap,
							    &rlen);
			if (err == 0 && esp_prov_sec1_apply(sec, resp, rlen) != 0) {
				err = -1;
			}
			if (err == 0) {
				LOG_DBG("HTTP #%u prov-scan: dispatch OK resp_len=%zu", req_num, rlen);
				respond_bin(cfd, resp, rlen, set_ck, false);
			} else {
				LOG_WRN("HTTP #%u prov-scan: dispatch failed -- no response", req_num);
				esp_prov_trace_note("http: prov-scan dispatch failed (no response)");
			}
		} else {
			respond_404(cfd);
		}

next_req:
		;
	}

	LOG_DBG("HTTP TCP session end (handled %u request(s))", http_req_count);
}

static void http_server_thread(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	int64_t last_idle_log = k_uptime_get();

	if (s_listen_fd < 0) {
		LOG_ERR("HTTP server thread: invalid listen fd");
		return;
	}

	LOG_DBG("HTTP server thread running, poll TCP :%u%s (idle log every 10s if no client)",
		LISTEN_PORT, (s_tls_probe_fd >= 0) ? " and :443 (HTTPS probes)" : "");

	while (!prov_http_dns_abort()) {
		struct zsock_pollfd pfds[2];
		int nfds = 1;

		pfds[0].fd = s_listen_fd;
		pfds[0].events = ZSOCK_POLLIN;
		if (s_tls_probe_fd >= 0) {
			pfds[1].fd = s_tls_probe_fd;
			pfds[1].events = ZSOCK_POLLIN;
			nfds = 2;
		}

		int pr = zsock_poll(pfds, nfds, 500);

		if (pr < 0) {
			LOG_WRN("HTTP zsock_poll failed errno=%d", errno);
			break;
		}

		bool got_http = (pfds[0].revents & ZSOCK_POLLIN) != 0;
		bool got_tls = (nfds > 1) && ((pfds[1].revents & ZSOCK_POLLIN) != 0);

		if (!got_http && !got_tls) {
			int64_t now = k_uptime_get();

			if (now - last_idle_log >= (int64_t)MSEC_PER_SEC * 10LL) {
				last_idle_log = now;
				LOG_DBG("HTTP: listen idle (no new inbound TCP on :%u%s in last ~10s). "
					"PoP is HTTP :%u; bursts of :443 are captive TLS probes, not this timer.",
					LISTEN_PORT, (s_tls_probe_fd >= 0) ? "/:443" : "", LISTEN_PORT);
			}
			continue;
		}

		if (got_tls) {
			int tfd = zsock_accept(s_tls_probe_fd, NULL, NULL);

			if (tfd >= 0) {
				LOG_DBG("TCP accept on :%u (TLS/HTTPS probe to poisoned DNS IP) -- "
					"closing (no TLS server; open Espressif app -> SoftAP uses HTTP :%u)",
					TLS_PROBE_PORT, LISTEN_PORT);
#if IS_ENABLED(CONFIG_ESP_PROV_SOFTAP_NET_HEX)
				prov_tcp_peek_log(tfd, "TCP:443", 256U);
#endif
				(void)zsock_shutdown(tfd, ZSOCK_SHUT_RDWR);
				zsock_close(tfd);
				last_idle_log = k_uptime_get();
			}
		}

		if (!got_http) {
			continue;
		}

		int cfd = zsock_accept(s_listen_fd, NULL, NULL);

		if (cfd < 0) {
			if (errno == ENFILE) {
				LOG_WRN("HTTP accept failed ENFILE (%d): global fd table full "
					"(raise CONFIG_ZVFS_OPEN_MAX in prj.conf)", errno);
			} else {
				LOG_WRN("HTTP accept failed errno=%d", errno);
			}
			continue;
		}

		last_idle_log = k_uptime_get();

		struct sockaddr_in peer = { 0 };
		socklen_t plen = sizeof(peer);

		if (zsock_getpeername(cfd, (struct sockaddr *)&peer, &plen) == 0 &&
		    peer.sin_family == AF_INET) {
			char ipstr[NET_IPV4_ADDR_LEN];

			(void)net_addr_ntop(AF_INET, &peer.sin_addr, ipstr, sizeof(ipstr));
			/* Debug-only: proves the phone reached our HTTP listener via
			 * SoftAP (separate from BLE GATT). If you see DHCP allocation but
			 * no HTTP accept, the phone associated but never opened TCP :80.
			 */
			LOG_DBG("HTTP TCP accept from %s:%u (SoftAP client)",
				ipstr, (unsigned int)ntohs(peer.sin_port));
		} else {
			LOG_WRN("HTTP accept: getpeername failed or not IPv4");
		}

#if IS_ENABLED(CONFIG_ESP_PROV_SOFTAP_NET_HEX)
		prov_tcp_peek_log(cfd, "TCP:80", 512U);
#endif

		/* Push small HTTP responses promptly (avoids Nagle + tiny recv delays on SoftAP). */
		{
			int nd = 1;

			(void)zsock_setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &nd, sizeof(nd));
		}

		/* Short RCVTIMEO/SNDTIMEO so read/send loops can poll stop/cancel (see journal). */
		struct zsock_timeval ctv = { .tv_sec = 0, .tv_usec = 250000 };

		(void)zsock_setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &ctv, sizeof(ctv));
		(void)zsock_setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &ctv, sizeof(ctv));
		LOG_DBG("HTTP: awaiting request headers (SO_RCVTIMEO=%lums, SO_SNDTIMEO=same, NODELAY=on)",
			(long)(ctv.tv_sec * 1000 + ctv.tv_usec / 1000));

		atomic_set(&s_http_cfd, cfd);
		http_handle_client(cfd);
		/* If prov_shutdown_http_client_socket() already closed the fd (cancel/timeout), skip. */
		{
			int prev = atomic_set(&s_http_cfd, -1);

			if (prev >= 0) {
				(void)zsock_close(prev);
			}
		}
	}
}

#endif /* CONFIG_ESP_PROV_USE_SOFTAP -- HTTP/DNS handlers + threads */

static void prov_abort_net_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);

	/* Full teardown: sockets (noop if esp_prov_cancel() already shut them down) + BLE.
	 * In single-transport builds, the unbuilt-side call collapses to a no-op:
	 *   - SoftAP off -> prov_shutdown_prov_sockets() compiled out (no sockets to shut).
	 *   - BLE off    -> esp_prov_ble_stop() is the stub from esp_prov_ble.c.
	 */
#if IS_ENABLED(CONFIG_ESP_PROV_USE_SOFTAP)
	prov_shutdown_prov_sockets();
#endif
	esp_prov_ble_stop();
}

K_WORK_DEFINE(prov_abort_net_work, prov_abort_net_work_fn);

static void prov_cancel_apply(bool from_isr)
{
	esp_prov_shared_stop_request();
	if (!from_isr) {
		/* Thread path: preemptive socket shutdown before work runs (ISR must not
		 * call zsock_*).
		 */
#if IS_ENABLED(CONFIG_ESP_PROV_USE_SOFTAP)
		prov_shutdown_prov_sockets();
#endif
	}
	(void)k_work_submit(&prov_abort_net_work);
}

void esp_prov_cancel_system(void)
{
	prov_cancel_apply(false);
}

void esp_prov_cancel_isr(void)
{
	prov_cancel_apply(true);
}

void esp_prov_cancel(void)
{
	prov_cancel_apply(false);
}

int esp_prov_routine_run(struct esp_wifi_credentials *out)
{
	int ret = ESP_PROV_ERR_INTERNAL;
#if IS_ENABLED(CONFIG_ESP_PROV_USE_BLE)
	bool ble_up = false;
#endif
#if IS_ENABLED(CONFIG_ESP_PROV_USE_SOFTAP)
	int listen_fd = -1;

	s_listen_fd = -1;
	s_tls_probe_fd = -1;
#endif

	if (out == NULL) {
		return ESP_PROV_ERR_INTERNAL;
	}

	memset(out, 0, sizeof(*out));
	esp_prov_shared_setup(out);
	esp_prov_shared_reset();
	esp_prov_sec1_reset(esp_prov_sec1_http());
	esp_prov_sec1_reset(esp_prov_sec1_ble());

	s_have_cookie = false;

	k_mutex_lock(&s_transport_mu, K_FOREVER);
	s_transport_choice = ESP_PROV_TP_NONE;
	k_mutex_unlock(&s_transport_mu);
#if IS_ENABLED(CONFIG_ESP_PROV_USE_SOFTAP)
	atomic_clear(&s_softap_abandoned);
#endif

	LOG_DBG("Prov routine: delaying 2 s (RF/coexistence settle) before transport bring-up");
	k_sleep(K_SECONDS(2));

	/*
	 * Pre-seed CTR-DRBG in this calm RF window. Without this, the first
	 * esp_prov_sec1_transport_open() runs from ble_connected on the BT RX thread
	 * while SoftAP is pumping packets, and mbedtls_entropy_func returns -52
	 * (MBEDTLS_ERR_ENTROPY_SOURCE_FAILED) -- the BLE central is then dropped before
	 * any protocomm exchange. rng_ensure() is one-shot, so a successful prewarm
	 * here means later transport_open() calls (HTTP and BLE) skip the seed
	 * entirely. Keep it before AP enable / scan / BLE adv: HID adv is suspended
	 * by app_coordinator before this work item starts, no central is connected
	 * (ACL drained pre-handoff), no scan is in flight, so the entropy source can
	 * deliver. On failure we log and continue -- transport_open() will retry under
	 * the existing fallback path.
	 */
	if (esp_prov_sec1_rng_prewarm() != 0) {
		LOG_WRN("sec1: RNG prewarm failed in calm window -- first transport_open will retry "
			"(see references/journal.md: ctr_drbg_seed -52)");
	} else {
		LOG_DBG("sec1: CTR-DRBG seeded in calm window (BLE/HTTP transport_open will reuse)");
	}

#if IS_ENABLED(CONFIG_ESP_PROV_USE_SOFTAP)
	/* SoftAP bring-up matches samples/net/wifi/apsta_mode (see references/esp32_wifi_apsta.md):
	 *   1. Configure AP IPv4 + netmask + gw + start DHCPv4 server on s_ap
	 *   2. NET_REQUEST_WIFI_AP_ENABLE on net_if_get_wifi_sap()
	 *      -> esp32_wifi_ap_enable() -> esp_wifi_set_mode(APSTA) -> esp_wifi_start()
	 *
	 * First esp_wifi_start() is from AP enable. Do NOT call NET_REQUEST_WIFI_SCAN before
	 * AP enable (esp32_wifi_scan() calls esp_wifi_start(); that ordering caused EXCCAUSE 28).
	 *
	 * After AP is up, esp_prov_shared_prescan_after_ap() runs one scan (SAP net_if) and fills
	 * the cache -- same idea as Rust wifi_ap::scan_wifi_for_prov before serving HTTP/BLE, and
	 * as BLE-only path in Rust (ble_prov uses cached_scan_results(), no RF scan during GATT).
	 *
	 * ESP32 APSTA on Zephyr requires a local patch to drivers/wifi/esp32/src/esp_wifi_drv.c
	 * (SAP/STA state, TX iface, AP RX timing).  Re-apply after west update from
	 * references/patches/esp32-wifi-drv-apsta.patch -- see references/esp32_wifi_apsta.md. */

	s_ap = net_if_get_wifi_sap();
	if (s_ap == NULL) {
		LOG_ERR("no SoftAP interface");
		goto cleanup_early;
	}

	net_mgmt_init_event_callback(&s_ap_events_cb, ap_events_handler,
				     NET_EVENT_WIFI_AP_ENABLE_RESULT |
				     NET_EVENT_WIFI_AP_DISABLE_RESULT |
				     NET_EVENT_WIFI_AP_STA_CONNECTED |
				     NET_EVENT_WIFI_AP_STA_DISCONNECTED);
	net_mgmt_add_event_callback(&s_ap_events_cb);

	if (enable_dhcp_and_ip() != 0) {
		LOG_ERR("AP IPv4/DHCP setup failed");
		goto cleanup_prep;
	}

	if (wifi_ap_start() != 0) {
		LOG_ERR("AP enable failed");
		goto cleanup_prep;
	}

	esp_prov_shared_prescan_after_ap();

	LOG_INF("SoftAP \"" ESP_PROV_SOFTAP_SSID "\" at %s", CONFIG_ESP_PROV_SOFTAP_IPV4_GATEWAY);
	LOG_DBG("SAP iface %p up=%d carrier=%d",
		s_ap, (int)net_if_is_up(s_ap), (int)net_if_is_carrier_ok(s_ap));

	listen_fd = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listen_fd < 0) {
		LOG_ERR("socket");
		goto cleanup_ap;
	}

	int one = 1;

	zsock_setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	struct sockaddr_in sin = { 0 };

	sin.sin_family = AF_INET;
	sin.sin_port = htons(LISTEN_PORT);
	/* Bind to SoftAP address (matches Rust embassy-net: AP-only listener). With APSTA,
	 * INADDR_ANY can leave the stack accepting in a way that fails to deliver TCP to :80
	 * for phone -> 192.168.4.1 in some Zephyr + Wi-Fi offload combinations.
	 */
	if (net_addr_pton(AF_INET, CONFIG_ESP_PROV_SOFTAP_IPV4_GATEWAY, &sin.sin_addr) != 0) {
		LOG_ERR("inet_pton %s", CONFIG_ESP_PROV_SOFTAP_IPV4_GATEWAY);
		goto cleanup_sock;
	}

	if (zsock_bind(listen_fd, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
		LOG_WRN("bind %s:%d failed errno=%d -- retry INADDR_ANY",
			CONFIG_ESP_PROV_SOFTAP_IPV4_GATEWAY, LISTEN_PORT, errno);
		sin.sin_addr.s_addr = htonl(INADDR_ANY);
		if (zsock_bind(listen_fd, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
			LOG_ERR("bind port %d (any)", LISTEN_PORT);
			goto cleanup_sock;
		}
	}

	prov_sock_bind_to_sap_iface(listen_fd);

	if (zsock_listen(listen_fd, 4) != 0) {
		LOG_ERR("listen");
		goto cleanup_sock;
	}

	{
		int tfd = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		if (tfd >= 0) {
			zsock_setsockopt(tfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
			sin.sin_port = htons(TLS_PROBE_PORT);
			if (net_addr_pton(AF_INET, CONFIG_ESP_PROV_SOFTAP_IPV4_GATEWAY, &sin.sin_addr) == 0 &&
			    zsock_bind(tfd, (struct sockaddr *)&sin, sizeof(sin)) == 0) {
				prov_sock_bind_to_sap_iface(tfd);
				if (zsock_listen(tfd, 2) == 0) {
					s_tls_probe_fd = tfd;
					LOG_DBG("TCP :%u listen (HTTPS captive probes; close w/o TLS -- app uses HTTP :%u)",
						TLS_PROBE_PORT, LISTEN_PORT);
				} else {
					LOG_WRN(":443 listen failed errno=%d", errno);
					zsock_close(tfd);
				}
			} else {
				LOG_WRN(":443 bind failed errno=%d (HTTPS probes only)", errno);
				zsock_close(tfd);
			}
		}
	}

	LOG_INF("HTTP listen ready on port %u (threads will accept on SoftAP once STA associates)", LISTEN_PORT);

	s_listen_fd = listen_fd;
	k_thread_create(&http_thread_data, http_thread_stack,
			K_THREAD_STACK_SIZEOF(http_thread_stack), http_server_thread, NULL, NULL, NULL,
			K_PRIO_PREEMPT(10), 0, K_NO_WAIT);
	k_thread_name_set(&http_thread_data, "prov-http");
	k_thread_create(&dns_thread_data, dns_thread_stack,
			K_THREAD_STACK_SIZEOF(dns_thread_stack), dns_server_thread, NULL, NULL, NULL,
			K_PRIO_PREEMPT(10), 0, K_NO_WAIT);
	k_thread_name_set(&dns_thread_data, "prov-dns");
#endif /* CONFIG_ESP_PROV_USE_SOFTAP -- SoftAP setup, sockets, HTTP/DNS threads */

#if IS_ENABLED(CONFIG_ESP_PROV_USE_BLE)
	if (esp_prov_bt_enable() != 0) {
		LOG_WRN("Bluetooth init failed; continuing without BLE");
	} else if (esp_prov_ble_start() != 0) {
		LOG_WRN("BLE provisioning advertising failed; continuing without BLE");
	} else {
		ble_up = true;
	}
#endif /* CONFIG_ESP_PROV_USE_BLE */

	/* Wall-clock limit is owned by prov_controller (outside this thread). */
	while (true) {
		if (esp_prov_shared_wait_done(K_MSEC(200))) {
			ret = ESP_PROV_OK;
			break;
		}
		if (esp_prov_shared_stop_requested()) {
			ret = ESP_PROV_ERR_CANCELLED;
			break;
		}
	}

	esp_prov_shared_stop_request();

#if IS_ENABLED(CONFIG_ESP_PROV_USE_SOFTAP)
	/* k_thread_join is idempotent: if BLE-wins teardown already joined these threads
	 * (softap_shutdown_work_fn extension), the second call returns 0 immediately.
	 */
	(void)k_thread_join(&http_thread_data, K_SECONDS(30));
	(void)k_thread_join(&dns_thread_data, K_SECONDS(5));

	s_listen_fd = -1;

	if (s_tls_probe_fd >= 0) {
		zsock_close(s_tls_probe_fd);
		s_tls_probe_fd = -1;
	}
#endif

#if IS_ENABLED(CONFIG_ESP_PROV_USE_BLE)
	if (ble_up) {
		esp_prov_ble_stop();
		/* HID resume is owned by app_coordinator_on_provisioning_finished(). */
	}
#endif

#if IS_ENABLED(CONFIG_ESP_PROV_USE_SOFTAP)
	if (listen_fd >= 0) {
		zsock_close(listen_fd);
	}

	net_mgmt_del_event_callback(&s_ap_events_cb);
	wifi_ap_stop();
#endif
	esp_prov_sec1_reset(esp_prov_sec1_http());
	esp_prov_sec1_reset(esp_prov_sec1_ble());
	if (s_have_cookie) {
		(void)esp_prov_sec1_transport_close(esp_prov_sec1_http(), s_cookie_id);
	}
	s_have_cookie = false;
	esp_prov_shared_reset();

	return ret;

#if IS_ENABLED(CONFIG_ESP_PROV_USE_SOFTAP)
cleanup_sock:
	if (s_tls_probe_fd >= 0) {
		zsock_close(s_tls_probe_fd);
		s_tls_probe_fd = -1;
	}
	if (listen_fd >= 0) {
		zsock_close(listen_fd);
	}
cleanup_ap:
	net_mgmt_del_event_callback(&s_ap_events_cb);
	wifi_ap_stop();
	esp_prov_sec1_reset(esp_prov_sec1_http());
	esp_prov_sec1_reset(esp_prov_sec1_ble());
	s_have_cookie = false;
	esp_prov_shared_reset();
	return ret;

cleanup_prep:
	net_mgmt_del_event_callback(&s_ap_events_cb);
cleanup_early:
	esp_prov_sec1_reset(esp_prov_sec1_http());
	esp_prov_sec1_reset(esp_prov_sec1_ble());
	esp_prov_shared_reset();
	return ESP_PROV_ERR_INTERNAL;
#endif /* CONFIG_ESP_PROV_USE_SOFTAP -- error/cleanup labels */
}

int esp_prov_run(struct esp_wifi_credentials *out)
{
	return prov_controller_run_blocking(out);
}
