# `esp_provisioning` — component manual

Normative reference for this Zephyr module: layout, public API, Kconfig, protocol,
and integration requirements.

For **symptoms, root causes, and fixes** (build failures, SoftAP/BLE quirks, shell
sample pitfalls), use [`references/journal.md`](journal.md) — not this file.

---

## Overview

Out-of-tree Zephyr module implementing Espressif-style Wi‑Fi provisioning compatible
with the Espressif **ESP BLE Provisioning** phone app (protocomm + sec1 over BLE GATT
and/or SoftAP HTTP).

| Artifact | Path |
|----------|------|
| Module manifest | [`zephyr/module.yml`](../zephyr/module.yml) |
| Kconfig | [`zephyr/Kconfig`](../zephyr/Kconfig) |
| Build | [`zephyr/CMakeLists.txt`](../zephyr/CMakeLists.txt) |
| Public API | [`src/esp_prov.h`](../src/esp_prov.h) |
| Reference app | [`samples/esp_provisioning_shell/`](../samples/esp_provisioning_shell/) |

---

## Zephyr module vs west project

A **Zephyr module** provides `zephyr/module.yml` and is discovered via
`ZEPHYR_MODULES` / `EXTRA_ZEPHYR_MODULES` / west manifest `projects:` entries.

This repository is a **module**, not part of the Zephyr tree. Register it in your
manifest or pass the repo root on `ZEPHYR_EXTRA_MODULES` (quote paths on Windows).

Bootstrap workspace: [`samples/esp_provisioning_shell/west.yml`](../samples/esp_provisioning_shell/west.yml)
and [`samples/esp_provisioning_shell/README.md`](../samples/esp_provisioning_shell/README.md).

Example manifest entry:

```yaml
manifest:
  projects:
    - name: esp_provisioning
      url: <your_git_url>
      revision: <tag_or_sha>
      path: modules/lib/esp_provisioning
```

Integration steps:

1. `west update`
2. `CONFIG_ESP_PROVISIONING=y` and at least one transport in the app `prj.conf`
3. Satisfy transport dependencies (see [Consuming application requirements](#consuming-application-requirements))

---

## Reference application

[`samples/esp_provisioning_shell/`](../samples/esp_provisioning_shell/) is the
**reference Zephyr application**: menu-driven provisioning, Wi‑Fi test join, credential
display, NVS save. Use it as a template for Kconfig, overlays, and `west build` paths.
It is **not** part of the module binary — only documentation and sample code.

---

## Source layout (`src/`)

| File | Role |
|------|------|
| [`esp_prov.h`](../src/esp_prov.h) | Public API |
| [`esp_prov_internal.h`](../src/esp_prov_internal.h) | Internal shared declarations |
| [`prov_controller.c`](../src/prov_controller.c) | Session controller; `esp_prov_session` logging |
| [`esp_prov_run.c`](../src/esp_prov_run.c) | SoftAP: HTTP, captive DNS, DHCP/L3, AP enable |
| [`esp_prov_ble.c`](../src/esp_prov_ble.c) | BLE GATT transport |
| [`esp_prov_sec1.c`](../src/esp_prov_sec1.c) | sec1 (Curve25519 + AES-CTR, PSA RNG) |
| [`esp_prov_pb.c`](../src/esp_prov_pb.c) | Protobuf helpers (scan / config) |
| [`esp_prov_shared.c`](../src/esp_prov_shared.c) | Cross-transport state (scan cache, signals) |
| [`esp_prov_trace.c`](../src/esp_prov_trace.c) | Optional diagnostics (Kconfig-gated) |

---

## Scope

**In scope**

- One provisioning session returning **`struct esp_wifi_credentials`** (SSID + PSK)
- protocomm + sec1 over BLE and/or SoftAP
- SoftAP: DHCP, DNS (captive), HTTP endpoints required by the phone app
- BLE: GATT service with protocomm endpoints

**Out of scope**

- Persisting credentials (NVS/settings), STA connect, reboot, or product policy after success
- Managing unrelated radio users (caller must coordinate BLE/Wi‑Fi with HID, etc.)

The application wraps `esp_prov_run()` for persistence and post-provision behavior.

---

## Runtime architecture

- **`esp_prov_run()`** blocks the caller until success, cancel, or wall-clock timeout.
- Provisioning work runs on a dedicated **prov-routine** thread
  (`CONFIG_ESP_PROV_ROUTINE_STACK_SIZE`); SoftAP HTTP uses a separate worker
  (`CONFIG_ESP_PROV_HTTP_WORKER_STACK_SIZE`).
- Wall-clock timeout: `CONFIG_ESP_PROV_SESSION_TIMEOUT_SEC` (enforced by
  [`prov_controller.c`](../src/prov_controller.c)); BLE central disconnect alone does
  not end the session unless `CONFIG_ESP_PROV_BLE_IDLE_AFTER_DISCONNECT_SEC` applies.
- When `CONFIG_ESP_PROV_USE_BLE` is enabled, `esp_prov_run()` brings up the BLE
  controller internally (`bt_enable()`, settings, TX power) before starting the GATT
  transport. The application must call Zephyr `bt_enable()` itself only if it uses
  other BLE roles **before** the first `esp_prov_run()` in the same boot.

---

## Public API

Header: [`src/esp_prov.h`](../src/esp_prov.h)

### Types

```c
enum esp_prov_result {
	ESP_PROV_OK = 0,
	ESP_PROV_ERR_CANCELLED,
	ESP_PROV_ERR_TIMEOUT,
	ESP_PROV_ERR_NO_MEM,
	ESP_PROV_ERR_INTERNAL,
	ESP_PROV_ERR_NOT_IMPLEMENTED,
};

struct esp_wifi_credentials {
	char ssid[33];
	char psk[65];
};
```

### Functions

| Function | Description |
|----------|-------------|
| `int esp_prov_run(struct esp_wifi_credentials *out)` | Run session; on `ESP_PROV_OK`, fills `ssid` / `psk` (NUL-terminated). |
| `void esp_prov_cancel(void)` | Cancel from thread context; tears down transports immediately. |
| `void esp_prov_cancel_isr(void)` | Cancel from ISR (flag + workqueue only). |

### Macros

| Macro | Source |
|-------|--------|
| `ESP_PROV_DEFAULT_POP` | `CONFIG_ESP_PROV_POP` |
| `ESP_PROV_SOFTAP_SSID` | `CONFIG_ESP_PROV_SOFTAP_SSID` |

### Logging

Session lifecycle uses Zephyr log module **`esp_prov_session`**. Transport logs:
`esp_prov_softap`, `esp_prov_ble`, `esp_prov_pkt`. Level:
**`CONFIG_ESP_PROV_LOG_LEVEL`** (requires `CONFIG_LOG_MAX_LEVEL` ≥ that value in the app).

---

## Kconfig (`zephyr/Kconfig`)

Master switch: **`CONFIG_ESP_PROVISIONING`**. At least one of
**`CONFIG_ESP_PROV_USE_BLE`** or **`CONFIG_ESP_PROV_USE_SOFTAP`** must be enabled
(enforced at compile time in [`esp_prov_internal.h`](../src/esp_prov_internal.h)).

### Transports

| Symbol | Default | Depends on |
|--------|---------|------------|
| `CONFIG_ESP_PROV_USE_BLE` | `y` | `BT`, `BT_PERIPHERAL`, `BT_SMP`, `BT_SETTINGS`, `BT_GATT_DYNAMIC_DB` |
| `CONFIG_ESP_PROV_USE_SOFTAP` | `y` | `NETWORKING`, `NET_IPV4`, `NET_SOCKETS`, `NET_TCP`, `NET_UDP`, `NET_DHCPV4_SERVER`, `WIFI`, `NET_L2_WIFI_MGMT`, `NET_INTERFACE_NAME` |

### Session / identity

| Symbol | Default | Description |
|--------|---------|-------------|
| `CONFIG_ESP_PROV_POP` | `"abcd1234"` | sec1 proof-of-possession (must match phone app / QR). |
| `CONFIG_ESP_PROV_SOFTAP_SSID` | `"PROV_esp"` | SoftAP SSID; also BLE advertised name when BLE is used. |
| `CONFIG_ESP_PROV_SESSION_TIMEOUT_SEC` | `30` | Wall-clock limit for `esp_prov_run()` (0 = no limit). |
| `CONFIG_ESP_PROV_ROUTINE_STACK_SIZE` | `12288` | prov-routine thread stack. |

### BLE-only

| Symbol | Default | Description |
|--------|---------|-------------|
| `CONFIG_ESP_PROV_BLE_IDLE_AFTER_DISCONNECT_SEC` | `5` | End session if central stays disconnected (0 = off). |

### SoftAP-only

| Symbol | Default | Description |
|--------|---------|-------------|
| `CONFIG_ESP_PROV_HTTP_CLOSE_AFTER_PROTO_VER` | `y` | Send `Connection: close` after `/proto-ver`. |
| `CONFIG_ESP_PROV_HTTP_WORKER_STACK_SIZE` | `16384` | HTTP server thread stack. |
| `CONFIG_ESP_PROV_DNS_STACK_SIZE` | `6144` | Captive DNS thread stack. |
| `CONFIG_ESP_PROV_SOFTAP_IPV4_GATEWAY` | `192.168.4.1` | AP / gateway address. |
| `CONFIG_ESP_PROV_SOFTAP_IPV4_NETMASK` | `255.255.255.0` | AP netmask. |
| `CONFIG_ESP_PROV_SOFTAP_DHCP_POOL_BASE` | `192.168.4.10` | DHCP lease pool base. |

### Logging

| Symbol | Default | Description |
|--------|---------|-------------|
| `CONFIG_ESP_PROV_LOG_LEVEL` | `3` | Module log level (0=off … 4=debug); needs `LOG`. |

### Diagnostics (`ESP_PROV_DIAG_LEVEL` choice)

| Level | Effect |
|-------|--------|
| `ESP_PROV_DIAG_OFF` | No extra diagnostics. |
| `ESP_PROV_DIAG_USER` | Milestone traces. |
| `ESP_PROV_DIAG_EXTENDED` | Extended PDU summaries (`CONFIG_ESP_PROV_PKT_LOG`). |
| `ESP_PROV_DIAG_PACKETS` | Packet sniffing (may expose credentials; enables trace/probe flags). |

Derived options (when packets level selected): `CONFIG_ESP_PROV_APP_TRACE`,
`CONFIG_ESP_PROV_CONSOLE_PROBE`, `CONFIG_ESP_PROV_SOFTAP_NET_HEX`, etc.

---

## Consuming application requirements

Beyond this module’s Kconfig, the **application** must enable Zephyr subsystems the
transports depend on (Wi‑Fi, BLE, DHCP server, sockets, mbedTLS/PSA for sec1).

**SoftAP / network (typical)**

- `CONFIG_ESP32_WIFI_AP_STA_MODE=y` when STA and SoftAP run together (see reference
  [`samples/esp_provisioning_shell/prj.conf`](../samples/esp_provisioning_shell/prj.conf))
- DHCPv4 server on the AP interface; DNS and captive-portal behavior may require
  **`CONFIG_NET_DHCPV4_SERVER_OPTION_CAPTIVE_PORTAL`** in the **app** (Zephyr network
  stack option, not this module’s Kconfig)
- Adequate `CONFIG_NET_MAX_CONTEXTS`, heap, and HTTP-related stacks for probe bursts

**BLE (typical)**

- `CONFIG_BT_RX_STACK_SIZE` large enough for GATT + sec1 on the BT RX thread (reference
  sample uses 4096)
- `CONFIG_BT_GATT_CACHING` per product needs (see journal if clients misbehave)

**sec1 / crypto**

- `CONFIG_MBEDTLS`, PSA wants including **`CONFIG_PSA_WANT_ECC_MONTGOMERY_255`**
- Module [`zephyr/CMakeLists.txt`](../zephyr/CMakeLists.txt) may pull hostap `ecdh.c`
  when needed; `zephyr/module.yml` should list **`build.depends: [mbedtls]`**

**Module discovery**

- Module sources compile only when
  `CONFIG_ESP_PROVISIONING` and a transport are both enabled (see
  [`zephyr/CMakeLists.txt`](../zephyr/CMakeLists.txt)).

---

## SoftAP bring-up sequence (normative)

Implemented in [`src/esp_prov_run.c`](../src/esp_prov_run.c); aligned with Zephyr
`samples/net/wifi/apsta_mode`.

| Step | Action |
|------|--------|
| 1 | `net_if_get_wifi_sap()` — SoftAP interface |
| 2 | Configure IPv4 gateway, netmask, DHCP pool (`CONFIG_ESP_PROV_SOFTAP_IPV4_*`) |
| 3 | Start DHCP server on SAP **before** `NET_REQUEST_WIFI_AP_ENABLE` |
| 4 | Enable open AP: empty PSK string, `WIFI_SECURITY_TYPE_NONE` (not NULL PSK) |
| 5 | Start HTTP + captive DNS |
| 6 | Teardown: stop DHCP, then disable AP |

Do not issue `NET_REQUEST_WIFI_SCAN` before AP is enabled if the driver ties scan to
`esp_wifi_start()` (ordering constraint — details in journal).

---

## Protocol

### Transports

- **BLE:** GATT notify + write, protocomm endpoints
- **SoftAP:** HTTP on port 80, DNS for captive detection

### SoftAP HTTP endpoints

| Method / path | Purpose |
|---------------|---------|
| `GET` / `POST` `/proto-ver` | Protocol version JSON (plaintext) |
| `POST` `/prov-session` | sec0 / sec1 handshake |
| `POST` `/prov-config` | Wi‑Fi config protobuf (encrypted after sec1) |
| `POST` `/prov-scan` | Wi‑Fi scan protobuf (encrypted after sec1) |

### sec1 (summary)

1. Curve25519 key exchange + nonce  
2. PoP (`CONFIG_ESP_PROV_POP`) proves possession and keys AES-CTR  
3. Subsequent protocomm payloads are AES-CTR encrypted  

---

## External references

- Phone app: [Android](https://play.google.com/store/apps/details?id=com.espressif.provble), [iOS](https://apps.apple.com/us/app/esp-ble-provisioning/id1473590141)
- ESP-IDF background: [Wi‑Fi provisioning](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/provisioning/wifi_provisioning.html)
- Zephyr modules: [External projects](https://docs.zephyrproject.org/latest/develop/modules.html)

---

## Related documentation

| Document | Contents |
|----------|----------|
| [`references/journal.md`](journal.md) | Debugging, integration pitfalls, shell sample notes |
| [`samples/esp_provisioning_shell/README.md`](../samples/esp_provisioning_shell/README.md) | Build, boards, overlays, menu |
| [`README.md`](../README.md) | Repository entry point |
