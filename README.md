# `esp_provisioning` (Zephyr module)

Out-of-tree Zephyr module implementing Espressif-style Wi‑Fi provisioning compatible
with the Espressif **ESP BLE Provisioning** phone app (protocomm + sec1 over BLE GATT
and/or SoftAP HTTP).

This repository contains **only** the provisioning component.

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
