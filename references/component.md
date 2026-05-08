# `esp_provisioning` component (Zephyr module)

Out-of-tree Zephyr module implementing Espressif-style Wi‑Fi provisioning compatible
with the Espressif **ESP BLE Provisioning** phone app (protocomm + sec1 over BLE GATT
and/or SoftAP HTTP).

This repository contains **only** the provisioning component.

## Zephyr modules vs west projects

Zephyr’s **module** model and **west** are related but not the same. See
[Modules (External projects)](https://docs.zephyrproject.org/latest/develop/modules.html),
especially [Modules vs west projects](https://docs.zephyrproject.org/latest/develop/modules.html#modules-vs-west-projects).

- A **Zephyr module** is a repository that provides **`zephyr/module.yml`** so the build
  can pick up `CMakeLists.txt` and `Kconfig` via `ZEPHYR_MODULES` (see
  [Integrate modules in Zephyr build system](https://docs.zephyrproject.org/latest/develop/modules.html#integrate-modules-in-zephyr-build-system)).
- A **west project** is a line under `manifest: projects:` in a **`west.yml`**. It is
  often a module, but not always (e.g. tool-only repos).

This repo is a **module** (see `zephyr/module.yml`). The nested manifest in
[`samples/esp_provisioning_shell/west.yml`](../samples/esp_provisioning_shell/west.yml)
sets `manifest.self.path: esp-provisioning` so `west init` / `west update` keep this
repository beside **`zephyr`** and pull Zephyr with **`import: true`** (HAL/modules).

**Extra module paths:** Upstream documents `EXTRA_ZEPHYR_MODULES` (env, CMake, `.zephyrrc`).
Zephyr’s CMake also merges `ZEPHYR_EXTRA_MODULES` into the same list, so the reference
app can register this repo in
[`samples/esp_provisioning_shell/CMakeLists.txt`](../samples/esp_provisioning_shell/CMakeLists.txt)
without a separate `-D` when you build from inside the tree.

## Reference application (first product on this module)

The directory [`samples/esp_provisioning_shell`](../samples/esp_provisioning_shell/) is
the **reference / first** Zephyr application on `esp_provisioning`. Use it as the
template for Kconfig, `west build` paths, and (optionally) workspace bootstrap.
Onboarding: [`samples/esp_provisioning_shell/README.md`](../samples/esp_provisioning_shell/README.md)
and nested [`west.yml`](../samples/esp_provisioning_shell/west.yml).

## Source layout (`src/`)

| File | Role |
|------|------|
| `esp_prov.h` | Public API (session entry points, cancel, credentials output). |
| `esp_prov_internal.h` | Internal helpers shared across the module. |
| `prov_controller.{c,h}` | Wall-clock controller (`prov-routine` thread); **esp_prov_session** logs (session start / outcome). |
| `esp_prov_run.c` | SoftAP transport (HTTP server + captive DNS + DHCP/IP setup). |
| `esp_prov_ble.c` | BLE GATT transport (protocomm endpoints over notify + write). |
| `esp_prov_sec1.c` | sec1 crypto (ECDH + AES-CTR) using mbedTLS legacy APIs. |
| `esp_prov_pb.{c,h}` | Protobuf parsing/building helpers for scan/config messages. |
| `esp_prov_shared.c` | Cross-transport shared state: scan cache, finish/cancel signals. |
| `esp_prov_trace.c` | Optional PDU/packet tracing helpers (gated by Kconfig). |

## Scope / non-scope

- **Does**:
  - Run a provisioning session that yields **SSID + passphrase** (`struct esp_wifi_credentials`)
  - Implement protocomm and sec1 (Curve25519 + AES-CTR) over BLE GATT and/or SoftAP HTTP
  - Provide SoftAP services needed for the app (DHCP, captive DNS, HTTP endpoints)
  - Provide BLE provisioning GATT service (notify + write endpoints)
- **Does not**:
  - Persist credentials (settings/NVS) or connect STA after provisioning
  - Reboot, apply product policy, or manage product peripherals and services

Your application owns persistence and what happens after `esp_prov_run()` returns.

## Public API

Header: `src/esp_prov.h`

- `int esp_prov_run(struct esp_wifi_credentials *out);`
  - Blocks until success, cancel, or timeout
  - On success, fills `out->ssid` and `out->psk`
  - Session **start** and **result** lines use log module `esp_prov_session` (`CONFIG_ESP_PROV_LOG_LEVEL`)
- `void esp_prov_cancel(void);`
- `void esp_prov_cancel_isr(void);`
- `bool esp_prov_user_cancel_may_run(void);`
  - Gate for **user** cancel (button / GPIO): false until SoftAP/HTTP/DNS/BLE reach session ready; then optional `CONFIG_ESP_PROV_USER_CANCEL_COOLDOWN_MS`. Wall-clock timeout uses `esp_prov_cancel()` from the controller and is **not** gated here.

Wrap `esp_prov_run()` in your own function when the app must persist credentials or schedule STA join after success.

## Kconfig surface

Kconfig file: `zephyr/Kconfig`

- **Enable module**: `CONFIG_ESP_PROVISIONING=y`
- **Logging**:
  - `CONFIG_ESP_PROV_LOG_LEVEL` (0=off..4=debug)
- **Transports** (at least one required):
  - `CONFIG_ESP_PROV_USE_BLE`
  - `CONFIG_ESP_PROV_USE_SOFTAP`
- **Identity**:
  - `CONFIG_ESP_PROV_POP` (proof-of-possession)
  - `CONFIG_ESP_PROV_SOFTAP_SSID` (SoftAP SSID; also used as BLE advertising name)
- **Session**:
  - `CONFIG_ESP_PROV_SESSION_TIMEOUT_SEC`
  - `CONFIG_ESP_PROV_USER_CANCEL_COOLDOWN_MS`
- **SoftAP IPv4**:
  - `CONFIG_ESP_PROV_SOFTAP_IPV4_GATEWAY`
  - `CONFIG_ESP_PROV_SOFTAP_IPV4_NETMASK`
  - `CONFIG_ESP_PROV_SOFTAP_DHCP_POOL_BASE`
- **Diagnostics**:
  - `CONFIG_ESP_PROV_DIAG_LEVEL` and derived flags (`CONFIG_ESP_PROV_APP_TRACE`, etc.)

Note: some DHCP server behavior (DNS/captive-portal options) is controlled by Zephyr’s
network Kconfig in the consuming app (not by this module).

## Add to west manifest

This repo is meant to be consumed as a **Zephyr module** (not merged into the Zephyr
tree). Authoritative module policies:
[Modules (External projects)](https://docs.zephyrproject.org/latest/develop/modules.html).
External/contrib context:
[external components](https://docs.zephyrproject.org/latest/contribute/external.html).

### Bootstrap workspace from this repository

Use the nested manifest
[`samples/esp_provisioning_shell/west.yml`](../samples/esp_provisioning_shell/west.yml)
(`west init … --mf samples/esp_provisioning_shell/west.yml`, then `west update`).
See [`samples/esp_provisioning_shell/README.md`](../samples/esp_provisioning_shell/README.md).

### West workspace basics

- The **west topdir** contains `.west/`, `zephyr/`, and `modules/`.
- In the default layout, `.west/config` sets `manifest.path=zephyr`, so the active
  manifest is `zephyr/west.yml`.
- Pin Zephyr by checking out a tag/branch in `zephyr/`, then run `west update`.
- Don’t commit `.west/`.

### Add this module to your own manifest

Add a project entry (example):

```yaml
manifest:
  projects:
    - name: esp_provisioning
      url: <your_git_url_here>
      revision: <git_sha_or_tag>
      path: modules/lib/esp_provisioning
```

Then:

- `west update`
- Enable `CONFIG_ESP_PROVISIONING=y` and the required transport(s) in your app config

The module is registered via:
- `zephyr/module.yml`
- `zephyr/Kconfig`
- `zephyr/CMakeLists.txt`

### Checklist (for tooling / AI)

1. Enable **`CONFIG_ESP_PROVISIONING=y`** and at least one of **`CONFIG_ESP_PROV_USE_BLE`** /
   **`CONFIG_ESP_PROV_USE_SOFTAP`** in the app.
2. Ensure this repository is on **`ZEPHYR_MODULES`** (west discovery from your manifest,
   or `EXTRA_ZEPHYR_MODULES` / `ZEPHYR_EXTRA_MODULES`, or a project `CMakeLists.txt` that
   appends the module root).
3. Build the reference app at **`samples/esp_provisioning_shell`** or fork from it.
4. Optional: create a workspace using **`samples/esp_provisioning_shell/west.yml`** as
   described in that README.

## Protocol summary

The phone app uses Espressif **protocomm** over BLE GATT or SoftAP HTTP. After a sec1
handshake, protocomm payloads are encrypted with AES-CTR and carry Wi‑Fi scan/config
protobuf messages.

### SoftAP HTTP endpoints

- `GET /proto-ver` and `POST /proto-ver`: returns protocol version JSON (unencrypted)
- `POST /prov-session`: sec0/sec1 handshake messages
- `POST /prov-config`: Wi‑Fi SetConfig / ApplyConfig / GetStatus (encrypted after sec1)
- `POST /prov-scan`: Wi‑Fi scan messages (encrypted after sec1)

### sec1 (high level)

- Client and device exchange Curve25519 public keys + nonce
- PoP is used to prove possession and derive the AES-CTR stream
- After handshake, both sides apply AES-CTR to subsequent protocomm payloads

## SoftAP implementation checklist (integration reference)

Aligned with `samples/net/wifi/apsta_mode` and the implementation in `src/esp_prov_run.c`.

| Step | What to do | Notes |
|------|------------|-------|
| Interface | Use `net_if_get_wifi_sap()` | SoftAP net_if, not STA. |
| IPv4 + mask + gw | Set gw to AP address | Defaults are in `CONFIG_ESP_PROV_SOFTAP_IPV4_*`. |
| DHCP pool | Start DHCP server on SAP | Pool base: `CONFIG_ESP_PROV_SOFTAP_DHCP_POOL_BASE`. |
| Order | **DHCP + L3 first**, then AP enable | Same order as Zephyr sample. |
| Open AP | PSK = empty string + `WIFI_SECURITY_TYPE_NONE` | Don’t use a NULL PSK pointer. |
| Scan ordering | Don’t scan before AP enable | `NET_REQUEST_WIFI_SCAN` may call `esp_wifi_start()` in the driver. |
| Teardown | Stop DHCP, then disable AP | Keeps networking clean between sessions. |

## References

- Espressif phone app: [Android](https://play.google.com/store/apps/details?id=com.espressif.provble), [iOS](https://apps.apple.com/us/app/esp-ble-provisioning/id1473590141)
- Protocol background (ESP-IDF): https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/provisioning/wifi_provisioning.html
- Pitfalls and debugging: `references/journal.md`

