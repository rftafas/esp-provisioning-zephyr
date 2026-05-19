# esp_provisioning_shell

**Reference Zephyr application** for the [`esp_provisioning`](../../README.md) module: interactive console with menu-driven BLE and/or SoftAP provisioning, Wi‑Fi connection test, credential inspection, and persist-to-NVS + reboot.

Integration theory (Zephyr **modules** vs **west** projects, `module.yml`, extra modules): [`references/component.md`](../../references/component.md).

## Board selection

This sample is **not tied to one devkit**. The default build enables **BLE + SoftAP** provisioning (`prj.conf` + [`app.overlay`](app.overlay) to enable `&wifi`). Targets any **Espressif Wi‑Fi + BLE** board in your Zephyr tree; use transport overlays for BLE-only or SoftAP-only SoCs.

List candidates from your workspace root:

```text
west boards | findstr -i esp
```

Pick the full board id (including qualifiers when required), e.g. `esp32s3_devkitc/esp32s3/procpu` or `esp32c3_devkitm/esp32c3`. Use that value as `<board>` below.

| Example board id | SoC family |
|------------------|------------|
| `esp32s3_devkitc/esp32s3/procpu` | ESP32-S3 |
| `esp32c3_devkitm/esp32c3` | ESP32-C3 |
| `esp32_devkitc_wrover/esp32/procpu` | ESP32 (classic) |

Names change between Zephyr releases — always prefer `west boards` over this table. On SoCs without BLE (e.g. ESP32-S2) or without Wi‑Fi (e.g. ESP32-H2), use [`overlay-softap-only.conf`](overlay-softap-only.conf) or [`overlay-ble-only.conf`](overlay-ble-only.conf). Adjust heap/stack sizes in `prj.conf` if the link fails or the device resets under load.

## Workspace from this repo’s manifest (`west.yml`)

[`west.yml`](west.yml) lives **in this directory**. Use it to bootstrap a fresh West workspace that pulls Zephyr (`import: true`) and places this repository at `esp-provisioning/` next to `zephyr/`.

From an **empty** parent directory (recommended):

```text
west init -m <your-esp-provisioning-git-url> --mr main --mf samples/esp_provisioning_shell/west.yml my-workspace
cd my-workspace
west update
west build -b <board> esp-provisioning/samples/esp_provisioning_shell -d build-shell
```

To use a **local clone** instead of `-m`, run `west init -l <path-to-esp-provisioning-clone> --mf samples/esp_provisioning_shell/west.yml` from a directory whose **parents do not already contain a `.west`** folder that West would discover when resolving the real path of your clone (otherwise West may attach to that existing workspace). If you already keep Zephyr under `…/zephyrprojects/` with `.west` at the top, prefer **`west init -m`** into a new folder, or skip this section and use **Build** below with your existing workspace.

The `west build` app path is always **`…/esp-provisioning/samples/esp_provisioning_shell`** when this repo is checked out as `esp-provisioning/` (see `self.path` in `west.yml`).

## Build (existing Zephyr workspace)

If you **already** have a West + Zephyr workspace, you do **not** need `west.yml` here — point `west build` at **this directory** from your workspace root. The sample’s [`CMakeLists.txt`](CMakeLists.txt) appends the **esp-provisioning repository root** (two levels up) to `ZEPHYR_EXTRA_MODULES`, so you normally **do not** pass `-DZEPHYR_EXTRA_MODULES`.

```text
west build -b <board> C:/path/to/esp-provisioning/samples/esp_provisioning_shell -d build-shell
```

Replace `<board>` with your target (see **Board selection**). Replace the app path if your checkout lives elsewhere.

If you copy only the `samples/esp_provisioning_shell` tree out of this repo, point CMake at the module explicitly again, e.g. `-- "-DZEPHYR_EXTRA_MODULES=C:/path/to/esp-provisioning"`. On Windows/PowerShell, **quote** that define so the drive letter is not split.

[`sample.yaml`](sample.yaml) is for **Twister** and `west build -T sample.esp_provisioning.shell`; it does not replace the CMake module registration above.

### Transport variants

| Config | Effect |
|--------|--------|
| *(default `prj.conf` + `app.overlay`)* | BLE + SoftAP (`CONFIG_ESP32_WIFI_AP_STA_MODE=y`) |
| [`overlay-softap-only.conf`](overlay-softap-only.conf) | SoftAP only (`CONFIG_BT=n`) |
| [`overlay-ble-only.conf`](overlay-ble-only.conf) | BLE only |

Example (SoftAP-only on ESP32-S2):

```text
west build -b <board> C:/path/to/esp-provisioning/samples/esp_provisioning_shell -d build-shell-softap -- -DEXTRA_CONF_FILE=overlay-softap-only.conf
```

On boot the console prints which transports are compiled in. SoftAP needs a separate SAP `net_if` (APSTA mode); without it, STA and SoftAP share one interface and provisioning often fails with `AP IPv4/DHCP setup failed` — see [`references/journal.md`](../../references/journal.md).

## Operator flow

1. Flash `zephyr.hex` / `zephyr.bin` for `<board>` (your board’s usual `west flash` flow).
2. Open the serial console (UART or USB CDC per your board’s devicetree; **115200 8N1** is typical).
3. Use keys **1–5** as printed.
4. **Option 3** prints SSID/PSK in plaintext after you press **Y**; it then shows STA IPv4/netmask/gateway when available.
5. **Option 2** connects using credentials from the **last successful provisioning** in RAM when present; otherwise it uses **stored** `wifi_credentials` (first SSID in storage).
6. **Option 5** cold-reboots without saving credentials (contrast with **4**, which persists last provisioning to NVS first).

## Notes

- Default **`CONFIG_ESP32_WIFI_AP_STA_MODE=y`** matches Zephyr `samples/net/wifi/apsta_mode`. If SoftAP SSID/DHCP misbehaves on your Zephyr revision, check ESP32 Wi‑Fi driver/APSTA support and [`references/journal.md`](../../references/journal.md) before blaming the module.
- [`app.overlay`](app.overlay) enables `&wifi` and fixes `&intc` on common Espressif boards; per-board console routing (USB vs UART) can use `boards/<board>.overlay` (see `boards/esp32s3_devkitc_procpu.overlay`).
- Heap and thread stack sizes in `prj.conf` were tuned on a typical devkit; on smaller SoCs you may need to reduce `CONFIG_HEAP_MEM_POOL_SIZE` or stack options — see [`references/journal.md`](../../references/journal.md).
