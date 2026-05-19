# `esp_provisioning` (Zephyr module)

Out-of-tree Zephyr module implementing Espressif-style Wi‑Fi provisioning compatible
with the Espressif **ESP BLE Provisioning** phone app (protocomm + sec1 over BLE GATT
and/or SoftAP HTTP).

This repository contains **only** the provisioning component.

## Usage

### Integrate the module

1. Add this repository to your West workspace (manifest project or git submodule), e.g.
   `git@github.com:rftafas/esp-provisioning-zephyr.git` at `modules/esp-provisioning`.
2. Register the module before `find_package(Zephyr)` — see
   [`samples/esp_provisioning_shell/CMakeLists.txt`](samples/esp_provisioning_shell/CMakeLists.txt)
   (`list(APPEND ZEPHYR_EXTRA_MODULES <repo-root>)`).
3. In your app `prj.conf`, enable at minimum:
   - `CONFIG_ESP_PROVISIONING=y`
   - At least one of `CONFIG_ESP_PROV_USE_BLE` / `CONFIG_ESP_PROV_USE_SOFTAP`
   - `CONFIG_ESP_PROV_POP` (proof-of-possession for sec1)
   - `CONFIG_ESP_PROV_SOFTAP_SSID` when using SoftAP
   - mbedTLS / PSA options as in the [sample `prj.conf`](samples/esp_provisioning_shell/prj.conf)

Full integration checklist: [`references/component.md`](references/component.md).

### Build and try the reference app

Flash and exercise provisioning with
[`samples/esp_provisioning_shell`](samples/esp_provisioning_shell/README.md). Pick **your**
Espressif board from `west boards` (see the sample README for a generic `west build -b <board>`
template). The sample registers this module in CMake — you normally do **not** pass
`-DZEPHYR_EXTRA_MODULES` when building from inside the tree.

### Run a provisioning session (application code)

Header: [`src/esp_prov.h`](src/esp_prov.h). Typical flow:

1. If the app uses BLE outside provisioning, call Zephyr `bt_enable()` (and your settings
   policy) before the first `esp_prov_run()` in that boot; the module initializes BLE again
   internally when the BLE transport is enabled.
2. Stop conflicting radio users (other BLE services, STA traffic) per your product policy.
3. `struct esp_wifi_credentials creds;`
4. `int r = esp_prov_run(&creds);` — blocks until success, cancel, or wall-clock timeout.
5. On `ESP_PROV_OK`, use `creds.ssid` / `creds.psk` (persist and join STA in **your** app).
6. Handle `ESP_PROV_ERR_CANCELLED`, `ESP_PROV_ERR_TIMEOUT`, and other `esp_prov_result` values.
7. Abort: `esp_prov_cancel()` (thread) or `esp_prov_cancel_isr()` (ISR).

Session **start** and **outcome** logs use the `esp_prov_session` log module
(`CONFIG_ESP_PROV_LOG_LEVEL`). The module does **not** save credentials or connect STA —
wrap `esp_prov_run()` if you need that (see journal “Post-provision” entry).

### Phone app (operator)

Use the Espressif **ESP BLE Provisioning** app ([Android](https://play.google.com/store/apps/details?id=com.espressif.provble), [iOS](https://apps.apple.com/us/app/esp-ble-provisioning/id1473590141)):

- Transport: **BLE** or **SoftAP** (must match what you enabled in Kconfig).
- **PoP** must match `CONFIG_ESP_PROV_POP`.
- SoftAP: join the device AP (SSID = `CONFIG_ESP_PROV_SOFTAP_SSID`), then provision in the app.

### When something fails

See [`references/journal.md`](references/journal.md) — integration pitfalls, logging, captive
portal, and operator issues (e.g. [phone VPN breaking SoftAP provisioning](references/journal.md#phone-vpn-active--softap-provisioning-fails-or-never-reaches-device)).

## Component spec

See [`references/component.md`](references/component.md) (integration checklist, west wiring, Kconfig).

## Sample

Console menu application: [`samples/esp_provisioning_shell/`](samples/esp_provisioning_shell/README.md).

## Repository layout

| Path | Purpose |
|------|---------|
| `src/` | Module implementation + public header (`esp_prov.h`). |
| `zephyr/module.yml` | Zephyr module manifest. |
| `zephyr/Kconfig` | Module Kconfig surface. |
| `zephyr/CMakeLists.txt` | Module build integration. |
| `samples/` | Example applications consuming the module. |
| `references/` | Notes + journal. |

## License

SPDX-License-Identifier: **Apache-2.0** (see file headers in source).
