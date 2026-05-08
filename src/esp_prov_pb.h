/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal proto3 wire helpers for Espressif WiFi provisioning (session.proto,
 * sec1.proto, wifi_config.proto, wifi_scan.proto) -- no protoc dependency.
 */

#ifndef ESP_PROV_PB_H
#define ESP_PROV_PB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** One WiFi AP scan entry (maps to WiFiScanResult proto, WifiAuthMode enum). */
struct esp_prov_scan_ap {
	uint8_t ssid[33];   /* NUL-terminated, ssid_len valid bytes */
	uint8_t ssid_len;
	uint8_t channel;
	int8_t  rssi;
	uint8_t bssid[6];
	uint8_t auth;       /* WifiAuthMode: 0=Open,1=WEP,3=WPA2,6=WPA3,... */
};

/* session.proto + sec1.proto */
int esp_prov_pb_parse_session_request(const uint8_t *data, size_t len, uint32_t *sec_ver,
				      uint32_t *sec1_msg, const uint8_t **inner,
				      size_t *inner_len);

int esp_prov_pb_build_session_response(uint8_t *buf, size_t cap, size_t *out_len,
				       uint32_t sec_ver, const uint8_t *sec1_payload,
				       size_t sec1_plen);

/* sec1 inner messages */
int esp_prov_pb_parse_sc0(const uint8_t *data, size_t len, uint8_t pubkey32[32]);

int esp_prov_pb_parse_sc1(const uint8_t *data, size_t len, const uint8_t **verify,
			  size_t *verify_len);

int esp_prov_pb_build_sr0(uint8_t *buf, size_t cap, size_t *out_len, const uint8_t dev_pub[32],
			  const uint8_t rand16[16]);

int esp_prov_pb_build_sr1(uint8_t *buf, size_t cap, size_t *out_len, const uint8_t dev_verify[32]);

/* wifi_config.proto */
int esp_prov_pb_parse_wifi_config(const uint8_t *plain, size_t len, uint32_t *msg_type,
				  const uint8_t **ssid, size_t *ssid_len, const uint8_t **pass,
				  size_t *pass_len);

int esp_prov_pb_build_wifi_resp_set_config(uint8_t *buf, size_t cap, size_t *out_len);
int esp_prov_pb_build_wifi_resp_apply_config(uint8_t *buf, size_t cap, size_t *out_len);
int esp_prov_pb_build_wifi_resp_get_status_connecting(uint8_t *buf, size_t cap, size_t *out_len);
/** Connected: RespGetStatus with sta_state=Connected only (Rust parity; ssid args ignored). */
int esp_prov_pb_build_wifi_resp_get_status_connected(uint8_t *buf, size_t cap, size_t *out_len,
						     const uint8_t *ssid, size_t ssid_len);

/* wifi_scan.proto */
int esp_prov_pb_parse_scan_msg_type(const uint8_t *plain, size_t len, uint32_t *msg_type);

/** Parse CmdScanResult embedded in WiFiScanPayload -> start_index, count. */
int esp_prov_pb_parse_cmd_scan_result(const uint8_t *plain, size_t len,
				      uint32_t *start_index, uint32_t *req_count);

int esp_prov_pb_build_scan_resp_start(uint8_t *buf, size_t cap, size_t *out_len);

/** RespScanStatus: scan_finished=finished, result_count=count. */
int esp_prov_pb_build_scan_resp_status(uint8_t *buf, size_t cap, size_t *out_len,
				       uint32_t count, bool finished);

/**
 * RespScanResult: encode aps[start_index .. start_index+req_count] (clamped to ap_count).
 * Each entry is a WiFiScanResult (ssid, channel, rssi, bssid, auth).
 */
int esp_prov_pb_build_scan_resp_result(uint8_t *buf, size_t cap, size_t *out_len,
				       const struct esp_prov_scan_ap *aps, uint32_t ap_count,
				       uint32_t start_index, uint32_t req_count);

#endif /* ESP_PROV_PB_H */
