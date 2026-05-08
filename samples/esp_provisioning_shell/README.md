# esp_provisioning_shell

**Reference Zephyr application** for the [`esp_provisioning`](../../README.md) module (the first firmware built on this component): interactive console with menu-driven BLE and/or SoftAP provisioning, Wi‑Fi connection test, credential inspection, and persist-to-NVS + reboot.

Integration theory (Zephyr **modules** vs **west** projects, `module.yml`, extra modules): [`references/component.md`](../../references/component.md).

## Workspace from this repo’s manifest (`west.yml`)

[`west.yml`](west.yml) lives **in this directory**. Use it to bootstrap a fresh West workspace that pulls Zephyr (`import: true`) and places this repository at `esp-provisioning/` next to `zephyr/`.

From an **empty** parent directory (recommended):

```text
west init -m <your-esp-provisioning-git-url> --mr main --mf samples/esp_provisioning_shell/west.yml my-workspace
cd my-workspace
west update
west build -b esp32s3_devkitc/esp32s3/procpu esp-provisioning/samples/esp_provisioning_shell -d build-shell-s3
```

To use a **local clone** instead of `-m`, run `west init -l <path-to-esp-provisioning-clone> --mf samples/esp_provisioning_shell/west.yml` from a directory whose **parents do not already contain a `.west`** folder that West would discover when resolving the real path of your clone (otherwise West may attach to that existing workspace). If you already keep Zephyr under `…/zephyrprojects/` with `.west` at the top, prefer **`west init -m`** into a new folder, or skip this section and use **Build** below with your existing workspace.

Adjust the board (`west boards | findstr esp32`). The `west build` app path is always **`…/esp-provisioning/samples/esp_provisioning_shell`** when this repo is checked out as `esp-provisioning/` (see `self.path` in `west.yml`).

## Build (existing Zephyr workspace)

If you **already** have a West + Zephyr workspace, you do **not** need `west.yml` here—point `west build` at **this directory** from your workspace root. The sample’s [`CMakeLists.txt`](CMakeLists.txt) appends the **esp-provisioning repository root** (two levels up) to `ZEPHYR_EXTRA_MODULES`, so you normally **do not** pass `-DZEPHYR_EXTRA_MODULES`.

Example (ESP32-S3 USB-JTAG console):

```text
west build -b esp32s3_devkitc/esp32s3/procpu C:/path/to/esp-provisioning/samples/esp_provisioning_shell -d build-shell-s3
```

Example (ESP32-C3):

```text
west build -b esp32c3_devkitm/esp32c3 C:/path/to/esp-provisioning/samples/esp_provisioning_shell -d build-shell-c3
```

Adjust the board target if yours differs (`west boards | findstr esp32`).

If you copy only the `samples/esp_provisioning_shell` tree out of this repo, point CMake at the module explicitly again, e.g. `-- "-DZEPHYR_EXTRA_MODULES=C:/path/to/esp-provisioning"`. On Windows/PowerShell, **quote** that define so the drive letter is not split.

[`sample.yaml`](sample.yaml) is for **Twister** and `west build -T sample.esp_provisioning.shell`; it does not replace the CMake module registration above.

### Transport variants

| Merge file | Effect |
|------------|--------|
| *(default `prj.conf`)* | BLE + SoftAP |
| [`conf-softap-only.conf`](conf-softap-only.conf) | SoftAP only (`CONFIG_BT=n`) |
| [`conf-ble-only.conf`](conf-ble-only.conf) | BLE only |

Example:

```text
west build ... C:/path/to/esp-provisioning/samples/esp_provisioning_shell -d build-softap -- -DEXTRA_CONF_FILE=conf-softap-only.conf
```

## Operator flow

1. Flash `zephyr.hex` / `zephyr.bin` and open the UART console (115200 8N1 typical).
2. Use keys **1–4** as printed.
3. **Option 3** prints SSID/PSK in plaintext after you press **Y**; it then shows STA IPv4/netmask/gateway when available.
4. **Option 2** connects using credentials from the **last successful provisioning** in RAM when present; otherwise it uses **stored** `wifi_credentials` (first SSID in storage).

## Notes

- Default configuration keeps **`CONFIG_ESP32_WIFI_AP_STA_MODE=n`** so the sample builds on Zephyr trees where concurrent AP+STA needs extra driver support; enable AP+STA in your own app only if your Zephyr/Wi‑Fi stack supports it for your board.
- No devicetree overlay is required for this sample; options are Kconfig-only.
