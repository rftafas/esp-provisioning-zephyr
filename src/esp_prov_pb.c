/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "esp_prov_pb.h"

#include <stdbool.h>
#include <string.h>

struct pb_r {
	const uint8_t *p;
	size_t rem;
};

static int pb_err(struct pb_r *r)
{
	return r->rem > 0 ? -1 : -1;
}

static bool pb_pull_tag(struct pb_r *r, uint32_t *field, uint32_t *wire)
{
	if (r->rem == 0U) {
		return false;
	}
	uint64_t key = 0U;
	size_t i = 0U;
	while (i < r->rem && i < 10U) {
		uint8_t b = r->p[i];

		key |= (uint64_t)(b & 0x7fU) << (7U * i);
		i++;
		if ((b & 0x80U) == 0U) {
			break;
		}
	}
	if (i == 0U || i >= r->rem) {
		return false;
	}
	r->p += i;
	r->rem -= i;
	*wire = (uint32_t)(key & 7U);
	*field = (uint32_t)(key >> 3);
	return true;
}

static bool pb_pull_varint(struct pb_r *r, uint64_t *v)
{
	*v = 0U;
	size_t i = 0U;

	while (i < r->rem && i < 10U) {
		uint8_t b = r->p[i];

		*v |= (uint64_t)(b & 0x7fU) << (7U * i);
		i++;
		if ((b & 0x80U) == 0U) {
			r->p += i;
			r->rem -= i;
			return true;
		}
	}
	return false;
}

static bool pb_pull_bytes(struct pb_r *r, const uint8_t **out, size_t *len)
{
	uint64_t l = 0U;

	if (!pb_pull_varint(r, &l) || l > r->rem) {
		return false;
	}
	*out = r->p;
	*len = (size_t)l;
	r->p += (size_t)l;
	r->rem -= (size_t)l;
	return true;
}

static void pb_skip_field(struct pb_r *r, uint32_t wire)
{
	if (wire == 0U) {
		uint64_t dummy = 0U;

		(void)pb_pull_varint(r, &dummy);
	} else if (wire == 2U) {
		const uint8_t *dummy = NULL;
		size_t l = 0U;

		(void)pb_pull_bytes(r, &dummy, &l);
	} else if (wire == 5U) {
		if (r->rem >= 4U) {
			r->p += 4U;
			r->rem -= 4U;
		}
	} else if (wire == 1U) {
		if (r->rem >= 8U) {
			r->p += 8U;
			r->rem -= 8U;
		}
	}
}

static size_t pb_put_varint(uint8_t *buf, uint64_t v)
{
	size_t n = 0U;

	while (v >= 0x80U) {
		buf[n++] = (uint8_t)(v | 0x80U);
		v >>= 7;
	}
	buf[n++] = (uint8_t)v;
	return n;
}

/* Encode tag (field<<3)|wire for wire=2 then varint len then data */
static size_t pb_encode_ld(uint8_t *buf, size_t cap, uint32_t field, const void *data, size_t dlen)
{
	uint32_t tag = (field << 3) | 2U;
	uint8_t tbuf[12];
	size_t tn = pb_put_varint(tbuf, tag);
	uint8_t lbuf[12];
	size_t ln = pb_put_varint(lbuf, dlen);

	if (tn + ln + dlen > cap) {
		return 0U;
	}
	if (dlen > 0U && data == NULL) {
		return 0U;
	}
	memcpy(buf, tbuf, tn);
	memcpy(buf + tn, lbuf, ln);
	if (dlen > 0U) {
		memcpy(buf + tn + ln, data, dlen);
	}
	return tn + ln + dlen;
}

int esp_prov_pb_parse_session_request(const uint8_t *data, size_t len, uint32_t *sec_ver,
				      uint32_t *sec1_msg, const uint8_t **inner, size_t *inner_len)
{
	struct pb_r r = { data, len };
	uint32_t sv = 0xffffffffU;
	const uint8_t *sec1 = NULL;
	size_t sec1_sz = 0U;

	*sec_ver = 0U;
	*sec1_msg = 0U;
	*inner = NULL;
	*inner_len = 0U;

	while (r.rem > 0U) {
		uint32_t f = 0U, w = 0U;

		if (!pb_pull_tag(&r, &f, &w)) {
			return pb_err(&r);
		}
		if (f == 2U && w == 0U) {
			uint64_t v = 0U;

			if (!pb_pull_varint(&r, &v)) {
				return -1;
			}
			sv = (uint32_t)v;
		} else if (f == 11U && w == 2U) {
			if (!pb_pull_bytes(&r, &sec1, &sec1_sz)) {
				return -1;
			}
		} else {
			pb_skip_field(&r, w);
		}
	}

	if (sv == 0xffffffffU || sec1 == NULL) {
		return -1;
	}
	*sec_ver = sv;

	struct pb_r s = { sec1, sec1_sz };
	uint32_t msg = 0xffffffffU;
	uint32_t found_field = 0U;
	const uint8_t *in = NULL;
	size_t in_sz = 0U;

	while (s.rem > 0U) {
		uint32_t f = 0U, w = 0U;

		if (!pb_pull_tag(&s, &f, &w)) {
			return -1;
		}
		if (f == 1U && w == 0U) {
			uint64_t v = 0U;

			if (!pb_pull_varint(&s, &v)) {
				return -1;
			}
			msg = (uint32_t)v;
		} else if ((f == 20U || f == 21U || f == 22U || f == 23U) && w == 2U) {
			found_field = f;
			if (!pb_pull_bytes(&s, &in, &in_sz)) {
				return -1;
			}
		} else {
			pb_skip_field(&s, w);
		}
	}

	if (in == NULL) {
		return -1;
	}
	/*
	 * proto3 omits fields whose value equals the type default (0).
	 * Session_Command0 = 0, so the phone never encodes field 1 when sending
	 * the first handshake step. Infer msg type from which oneof field arrived:
	 * sc0=20 -> 0, sr0=21 -> 1, sc1=22 -> 2, sr1=23 -> 3.
	 */
	if (msg == 0xffffffffU) {
		if (found_field < 20U || found_field > 23U) {
			return -1;
		}
		msg = found_field - 20U;
	}
	*sec1_msg = msg;
	*inner = in;
	*inner_len = in_sz;
	return 0;
}

int esp_prov_pb_build_session_response(uint8_t *buf, size_t cap, size_t *out_len, uint32_t sec_ver,
				       const uint8_t *sec1_payload, size_t sec1_plen)
{
	uint8_t tmp[384];
	size_t n = 0U;
	uint8_t vbuf[12];
	size_t vn = pb_put_varint(vbuf, sec_ver);

	if (1U + vn > sizeof(tmp)) {
		return -1;
	}
	tmp[n++] = (uint8_t)((2U << 3) | 0U);
	memcpy(tmp + n, vbuf, vn);
	n += vn;

	size_t m = pb_encode_ld(tmp + n, sizeof(tmp) - n, 11U, sec1_payload, sec1_plen);

	if (m == 0U) {
		return -1;
	}
	n += m;
	if (n > cap) {
		return -1;
	}
	memcpy(buf, tmp, n);
	*out_len = n;
	return 0;
}

int esp_prov_pb_parse_sc0(const uint8_t *data, size_t len, uint8_t pubkey32[32])
{
	struct pb_r r = { data, len };

	while (r.rem > 0U) {
		uint32_t f = 0U, w = 0U;

		if (!pb_pull_tag(&r, &f, &w)) {
			return -1;
		}
		if (f == 1U && w == 2U) {
			const uint8_t *b = NULL;
			size_t bl = 0U;

			if (!pb_pull_bytes(&r, &b, &bl) || bl != 32U) {
				return -1;
			}
			memcpy(pubkey32, b, 32U);
			return 0;
		}
		pb_skip_field(&r, w);
	}
	return -1;
}

int esp_prov_pb_parse_sc1(const uint8_t *data, size_t len, const uint8_t **verify, size_t *verify_len)
{
	struct pb_r r = { data, len };

	while (r.rem > 0U) {
		uint32_t f = 0U, w = 0U;

		if (!pb_pull_tag(&r, &f, &w)) {
			return -1;
		}
		if (f == 2U && w == 2U) {
			return pb_pull_bytes(&r, verify, verify_len) ? 0 : -1;
		}
		pb_skip_field(&r, w);
	}
	return -1;
}

int esp_prov_pb_build_sr0(uint8_t *buf, size_t cap, size_t *out_len, const uint8_t dev_pub[32],
			  const uint8_t rand16[16])
{
	/* Sec1Payload: msg=Session_Response0 (1), sr0 message */
	uint8_t sr0[80];
	size_t sn = 0U;

	/* SessionResp0: status=Success(0) field1, device_pubkey field2, device_random field3 */
	sr0[sn++] = (1U << 3) | 0U;
	sr0[sn++] = 0U; /* Success */
	size_t m = pb_encode_ld(sr0 + sn, sizeof(sr0) - sn, 2U, dev_pub, 32U);

	if (m == 0U) {
		return -1;
	}
	sn += m;
	m = pb_encode_ld(sr0 + sn, sizeof(sr0) - sn, 3U, rand16, 16U);
	if (m == 0U) {
		return -1;
	}
	sn += m;

	uint8_t outer[128];
	size_t on = 0U;

	outer[on++] = (1U << 3) | 0U;
	outer[on++] = 1U; /* Session_Response0 */
	m = pb_encode_ld(outer + on, sizeof(outer) - on, 21U, sr0, sn);
	if (m == 0U) {
		return -1;
	}
	on += m;
	if (on > cap) {
		return -1;
	}
	memcpy(buf, outer, on);
	*out_len = on;
	return 0;
}

int esp_prov_pb_build_sr1(uint8_t *buf, size_t cap, size_t *out_len, const uint8_t dev_verify[32])
{
	uint8_t sr1[48];
	size_t sn = 0U;

	sr1[sn++] = (1U << 3) | 0U;
	sr1[sn++] = 0U;
	size_t m = pb_encode_ld(sr1 + sn, sizeof(sr1) - sn, 3U, dev_verify, 32U);

	if (m == 0U) {
		return -1;
	}
	sn += m;

	uint8_t outer[80];
	size_t on = 0U;

	outer[on++] = (1U << 3) | 0U;
	outer[on++] = 3U; /* Session_Response1 */
	m = pb_encode_ld(outer + on, sizeof(outer) - on, 23U, sr1, sn);
	if (m == 0U) {
		return -1;
	}
	on += m;
	if (on > cap) {
		return -1;
	}
	memcpy(buf, outer, on);
	*out_len = on;
	return 0;
}

int esp_prov_pb_parse_wifi_config(const uint8_t *plain, size_t len, uint32_t *msg_type,
				  const uint8_t **ssid, size_t *ssid_len, const uint8_t **pass,
				  size_t *pass_len)
{
	struct pb_r r = { plain, len };

	*msg_type = 0xffffffffU;
	*ssid = NULL;
	*ssid_len = 0U;
	*pass = NULL;
	*pass_len = 0U;

	while (r.rem > 0U) {
		uint32_t f = 0U, w = 0U;

		if (!pb_pull_tag(&r, &f, &w)) {
			return -1;
		}
		if (f == 1U && w == 0U) {
			uint64_t v = 0U;

			if (!pb_pull_varint(&r, &v)) {
				return -1;
			}
			*msg_type = (uint32_t)v;
		} else if (f == 12U && w == 2U) {
			const uint8_t *sub = NULL;
			size_t sl = 0U;

			if (!pb_pull_bytes(&r, &sub, &sl)) {
				return -1;
			}
			struct pb_r c = { sub, sl };

			while (c.rem > 0U) {
				uint32_t cf = 0U, cw = 0U;

				if (!pb_pull_tag(&c, &cf, &cw)) {
					return -1;
				}
				if (cf == 1U && cw == 2U) {
					if (!pb_pull_bytes(&c, ssid, ssid_len)) {
						return -1;
					}
				} else if (cf == 2U && cw == 2U) {
					if (!pb_pull_bytes(&c, pass, pass_len)) {
						return -1;
					}
				} else {
					pb_skip_field(&c, cw);
				}
			}
		} else {
			pb_skip_field(&r, w);
		}
	}
	/* proto3 omits field 1 when value == 0 (TypeCmdGetStatus = default). */
	if (*msg_type == 0xffffffffU) {
		*msg_type = 0U;
	}
	return 0;
}

static int wifi_outer(uint8_t *buf, size_t cap, size_t *out_len, uint32_t msg_enum,
		      uint32_t subfield, const void *sub, size_t sublen)
{
	uint8_t tmp[160];
	size_t n = 0U;

	tmp[n++] = (1U << 3) | 0U;
	tmp[n++] = (uint8_t)msg_enum;
	size_t m = pb_encode_ld(tmp + n, sizeof(tmp) - n, subfield, sub, sublen);

	if (m == 0U) {
		return -1;
	}
	n += m;
	if (n > cap) {
		return -1;
	}
	memcpy(buf, tmp, n);
	*out_len = n;
	return 0;
}

int esp_prov_pb_build_wifi_resp_set_config(uint8_t *buf, size_t cap, size_t *out_len)
{
	uint8_t inner[8];
	size_t n = 0U;

	inner[n++] = (1U << 3) | 0U;
	inner[n++] = 0U; /* Status Success */
	return wifi_outer(buf, cap, out_len, 3U, 13U, inner, n);
}

int esp_prov_pb_build_wifi_resp_apply_config(uint8_t *buf, size_t cap, size_t *out_len)
{
	uint8_t inner[8];
	size_t n = 0U;

	inner[n++] = (1U << 3) | 0U;
	inner[n++] = 0U;
	return wifi_outer(buf, cap, out_len, 5U, 15U, inner, n);
}

int esp_prov_pb_build_wifi_resp_get_status_connecting(uint8_t *buf, size_t cap, size_t *out_len)
{
	/* RespGetStatus: status=0, sta_state=Disconnected(2) -- matches earlier protocomm ports (not Connecting). */
	uint8_t inner[16];
	size_t n = 0U;

	inner[n++] = (1U << 3) | 0U;
	inner[n++] = 0U;
	inner[n++] = (2U << 3) | 0U;
	inner[n++] = 2U; /* WifiStationState.Disconnected */
	return wifi_outer(buf, cap, out_len, 1U, 11U, inner, n);
}

int esp_prov_pb_build_wifi_resp_get_status_connected(uint8_t *buf, size_t cap, size_t *out_len,
						     const uint8_t *ssid, size_t ssid_len)
{
	(void)ssid;
	(void)ssid_len;

	/*
	 * Rust `encode_resp_get_status(..., true)` sends only status + sta_state=Connected;
	 * it does not set the RespGetStatus `state` oneof. Nesting WifiConnectedState with
	 * only `ssid` (no ip4_addr) can cause the Espressif app to reject the payload when
	 * "checking provisioning status".
	 */
	uint8_t inner[16];
	size_t n = 0U;

	inner[n++] = (1U << 3) | 0U;
	inner[n++] = 0U;
	inner[n++] = (2U << 3) | 0U;
	inner[n++] = 0U; /* WifiStationState.Connected */
	return wifi_outer(buf, cap, out_len, 1U, 11U, inner, n);
}

int esp_prov_pb_parse_scan_msg_type(const uint8_t *plain, size_t len, uint32_t *msg_type)
{
	struct pb_r r = { plain, len };

	*msg_type = 0xffffffffU;
	while (r.rem > 0U) {
		uint32_t f = 0U, w = 0U;

		if (!pb_pull_tag(&r, &f, &w)) {
			return -1;
		}
		if (f == 1U && w == 0U) {
			uint64_t v = 0U;

			if (!pb_pull_varint(&r, &v)) {
				return -1;
			}
			*msg_type = (uint32_t)v;
		} else {
			pb_skip_field(&r, w);
		}
	}
	/* proto3 omits field 1 when value == 0 (TypeCmdScanStart = default). */
	if (*msg_type == 0xffffffffU) {
		*msg_type = 0U;
	}
	return 0;
}

int esp_prov_pb_build_scan_resp_start(uint8_t *buf, size_t cap, size_t *out_len)
{
	/* RespScanStart: empty submessage at field 11 */
	return wifi_outer(buf, cap, out_len, 1U, 11U, NULL, 0U);
}

int esp_prov_pb_build_scan_resp_status(uint8_t *buf, size_t cap, size_t *out_len,
				       uint32_t count, bool finished)
{
	uint8_t inner[16];
	size_t n = 0U;

	/*
	 * RespScanStatus inner fields -- matches Rust protocomm reference:
	 *   field 1 (varint): scan_finished (bool)
	 *   field 2 (varint): result_count  (uint32)
	 *
	 * Both fields are always encoded; proto3 treats zero-value as absent,
	 * so the phone sees finished=false / count=0 when not done yet.
	 */
	uint8_t vb[8];
	size_t vn;

	inner[n++] = (1U << 3) | 0U; /* field 1 = scan_finished */
	inner[n++] = finished ? 1U : 0U;
	vn = pb_put_varint(vb, count);
	inner[n++] = (2U << 3) | 0U; /* field 2 = result_count */
	memcpy(inner + n, vb, vn);
	n += vn;
	return wifi_outer(buf, cap, out_len, 3U, 13U, inner, n);
}

int esp_prov_pb_parse_cmd_scan_result(const uint8_t *plain, size_t len,
				      uint32_t *start_index, uint32_t *req_count)
{
	struct pb_r r = { plain, len };

	*start_index = 0U;
	*req_count   = 4U; /* proto3 default if absent */

	while (r.rem > 0U) {
		uint32_t f = 0U, w = 0U;

		if (!pb_pull_tag(&r, &f, &w)) {
			break;
		}
		if (f == 14U && w == 2U) {
			const uint8_t *inner = NULL;
			size_t inner_len = 0U;

			if (!pb_pull_bytes(&r, &inner, &inner_len)) {
				break;
			}
			struct pb_r s = { inner, inner_len };

			while (s.rem > 0U) {
				uint32_t sf = 0U, sw = 0U;

				if (!pb_pull_tag(&s, &sf, &sw)) {
					break;
				}
				if (sf == 1U && sw == 0U) {
					uint64_t v = 0U;

					if (pb_pull_varint(&s, &v)) {
						*start_index = (uint32_t)v;
					}
				} else if (sf == 2U && sw == 0U) {
					uint64_t v = 0U;

					if (pb_pull_varint(&s, &v)) {
						*req_count = (uint32_t)v;
					}
				} else {
					pb_skip_field(&s, sw);
				}
			}
		} else {
			pb_skip_field(&r, w);
		}
	}
	return 0;
}

int esp_prov_pb_build_scan_resp_result(uint8_t *buf, size_t cap, size_t *out_len,
				       const struct esp_prov_scan_ap *aps, uint32_t ap_count,
				       uint32_t start_index, uint32_t req_count)
{
	/*
	 * Encode RespScanResult (field 15 of WiFiScanPayload).
	 * Each WiFiScanResult entry: ssid(1,bytes), channel(2,varint),
	 * rssi(3,int32/varint sign-extended), bssid(4,bytes), auth(5,varint if!=0).
	 * Entries are repeated field 1 inside RespScanResult.
	 */
	uint8_t inner[480]; /* RespScanResult content */
	size_t ip = 0U;
	uint32_t end = start_index + req_count;

	if (end > ap_count) {
		end = ap_count;
	}

	for (uint32_t i = start_index; i < end; i++) {
		const struct esp_prov_scan_ap *ap = &aps[i];
		uint8_t entry[80];
		size_t ep = 0U;
		size_t m;

		/* ssid: field 1, bytes */
		m = pb_encode_ld(entry + ep, sizeof(entry) - ep, 1U, ap->ssid, ap->ssid_len);
		if (m == 0U) {
			continue;
		}
		ep += m;

		/* channel: field 2, varint */
		entry[ep++] = (2U << 3) | 0U;
		ep += pb_put_varint(entry + ep, ap->channel);

		/* rssi: field 3, int32 -- proto3 uses sign-extended varint */
		entry[ep++] = (3U << 3) | 0U;
		ep += pb_put_varint(entry + ep, (uint64_t)(int64_t)ap->rssi);

		/* bssid: field 4, bytes (6 octets) */
		m = pb_encode_ld(entry + ep, sizeof(entry) - ep, 4U, ap->bssid, 6U);
		if (m == 0U) {
			continue;
		}
		ep += m;

		/* auth: field 5, varint -- omit if Open (0) to save bytes */
		if (ap->auth != 0U) {
			entry[ep++] = (5U << 3) | 0U;
			ep += pb_put_varint(entry + ep, ap->auth);
		}

		/* wrap entry in RespScanResult.entries (field 1, repeated) */
		m = pb_encode_ld(inner + ip, sizeof(inner) - ip, 1U, entry, ep);
		if (m == 0U) {
			break; /* inner buffer full */
		}
		ip += m;
	}

	/* WiFiScanPayload: msg=5(TypeRespScanResult), status=0, field15=RespScanResult */
	uint8_t tmp[512];
	size_t n = 0U;

	tmp[n++] = (1U << 3) | 0U; /* field 1 (msg) */
	tmp[n++] = 5U;              /* TypeRespScanResult */
	tmp[n++] = (2U << 3) | 0U; /* field 2 (status) */
	tmp[n++] = 0U;              /* Success */

	size_t m = pb_encode_ld(tmp + n, sizeof(tmp) - n, 15U, inner, ip);

	if (m == 0U) {
		return -1;
	}
	n += m;
	if (n > cap) {
		return -1;
	}
	memcpy(buf, tmp, n);
	*out_len = n;
	return 0;
}
