# Provisioning journal (`esp_provisioning`)

Concise **Symptom / Root cause / Fix** entries for debugging and integrating this
module (SoftAP/BLE protocomm + sec1) and the reference
[`esp_provisioning_shell`](../samples/esp_provisioning_shell/) sample. This is not a
product or project log. For west/module setup and API, Kconfig, and integration specs: [component.md](component.md).

---

## How AI / humans should read this

Each entry has **`Search keys:`** — tokens from logs, link errors, or Kconfig symbols.
**Grep this file (or the build log) for a key first**, then read that entry’s three blocks.

**Scope:** Module integration (Kconfig, transports, sec1, SoftAP/BLE pitfalls) plus the
reference shell sample where noted. Entries marked **Shell sample** are sample-app bugs or
patterns, not module defects — still useful when copying that sample into a product app.

---

## Index

**Build / workspace**

- [Stale `zephyr_modules.txt` after `west update`](#stale-zephyr_modulestxt-after-west-update)
- [Undefined `mbedtls_ecdh_gen_public` / `mbedtls_ecdh_compute_shared` at link time](#undefined-mbedtls_ecdh_gen_public--mbedtls_ecdh_compute_shared-at-link-time)
- [Windows: `ZEPHYR_EXTRA_MODULES` drive-letter split](#windows-zephyr_extra_modules-drive-letter-split)
- [`esp-provisioning` breaks unrelated Zephyr test/sample builds (no transport selected)](#esp-provisioning-breaks-unrelated-zephyr-testsample-builds-no-transport-selected)

**Logging / diagnostics**

- [No useful `LOG_*` output from `esp_prov_*` modules](#no-useful-log_-output-from-esp_prov_-modules)
- [esp32s3_devkitc shell sample silent on native USB port (console pinned to UART0)](#esp32s3_devkitc-shell-sample-silent-on-native-usb-port-console-pinned-to-uart0)

**API / integration**

- [`esp_prov_bt_enable()` is not public API](#esp_prov_bt_enable-is-not-public-api)
- [Cancel API: immediate, no module debounce or GPIO](#cancel-api-immediate-no-module-debounce-or-gpio)

**Transport prerequisites**

- [Build fails: at least one transport must be enabled (`BUILD_ASSERT`)](#build-fails-at-least-one-transport-must-be-enabled-build_assert)

**SoftAP transport (HTTP / DNS / DHCP)**

- [Captive-portal probes dominate early traffic](#captive-portal-probes-dominate-early-traffic)
- [Phone VPN active — SoftAP provisioning fails or never reaches device](#phone-vpn-active--softap-provisioning-fails-or-never-reaches-device)
- [SoftAP bring-up crashes when scanning runs before AP enable](#softap-bring-up-crashes-when-scanning-runs-before-ap-enable)
- [`AP IPv4/DHCP setup failed` when STA is associated (single-mode build)](#ap-ipv4dhcp-setup-failed-when-sta-is-associated-single-mode-build)
- [TCP context exhaustion under probe bursts (`net_context_get(): -2`)](#tcp-context-exhaustion-under-probe-bursts-net_context_get--2)

**BLE transport (GATT)**

- [GATT caching / DB-hash mismatch](#gatt-caching--db-hash-mismatch)
- [BLE connect -> `EXCCAUSE` illegal instruction in `z_swap` (BT RX stack overflow)](#ble-connect---exccause-illegal-instruction-in-z_swap-bt-rx-stack-overflow)

**sec1 / PoP**

- [PoP mismatch](#pop-mismatch)
- [Entropy / CTR-DRBG seed failures under load](#entropy--ctr-drbg-seed-failures-under-load)
- [TF-PSA 1.0 (Zephyr 4.4): legacy `mbedtls_entropy_*` not linked](#tf-psa-10-zephyr-44-legacy-mbedtls_entropy_-not-linked)
- [sec1 X25519: undefined `mbedtls_ecp_*` / `mbedtls_mpi_*` (`PSA_WANT_ECC_MONTGOMERY_255`)](#sec1-x25519-undefined-mbedtls_ecp---mbedtls_mpi_-psa_want_ecc_montgomery_255)

**API / integration**

- [Post-provision: credentials / STA (app wraps `esp_prov_run()`)](#post-provision-credentials--sta-app-wraps-esp_prov_run)

**Shell sample (`esp_provisioning_shell`)**

- [SoftAP missing with AP_STA off or wrong net Kconfig](#shell-sample-softap-missing-with-ap_sta-off-or-wrong-net-kconfig)
- [Option 2: dangling stack pointers when joining from stored credentials](#shell-sample-option-2-dangling-stack-pointers-when-joining-from-stored-credentials)
- [Option 2: `NET_REQUEST_WIFI_CONNECT failed: -120` (`-EALREADY`)](#shell-sample-option-2-net_request_wifi_connect-failed--120--ealready)

---

## Build / workspace

### Stale `zephyr_modules.txt` after `west update`

**Date:** 2026-05-15

**Search keys:** `tf-psa-crypto`, `zephyr_modules.txt`, `west build -p always`, `west topdir`,
`mbedtls/tf-psa-crypto`, `west list`

**Symptom:** CMake still looks for `mbedtls/tf-psa-crypto`, but `west list` shows
`tf-psa-crypto` at `modules/crypto/tf-psa-crypto` — or the build fails in TF-PSA / mbedtls
paths that do not match the updated module layout.

**Root cause:** The build directory’s `zephyr_modules.txt` can be stale (e.g. missing the
`tf-psa-crypto` line) after `west update` or module path changes, so `zephyr_module.py` does
not wire the tree CMake expects.

**Fix:** Run `west build -p always` from the **West topdir** (`west topdir`) so Zephyr
regenerates `zephyr_modules.txt` and module discovery matches `west list`.

---

### Undefined `mbedtls_ecdh_gen_public` / `mbedtls_ecdh_compute_shared` at link time

**Date:** 2026-05-15

**Search keys:** `mbedtls_ecdh_gen_public`, `mbedtls_ecdh_compute_shared`, `removed/ecdh.c`,
`build.depends`, `module.yml`, `TARGET mbedTLS`

**Symptom:** Linker undefined references to `mbedtls_ecdh_gen_public` /
`mbedtls_ecdh_compute_shared` (often from hostap `removed/ecdh.c`), even with
`CONFIG_MBEDTLS=y`.

**Root cause:** [zephyr/CMakeLists.txt](../zephyr/CMakeLists.txt) appends hostap’s `ecdh.c` to
`builtin` only when the `mbedTLS` CMake target already exists. Without a module-level
`depends:` on **mbedtls**, CMake can process `esp_provisioning` before `mbedtls`, so that
block is skipped and the ECDH glue never links.

**Fix:** Ensure [zephyr/module.yml](../zephyr/module.yml) includes `build.depends: [mbedtls]`
under `build:`.

---

### Windows: `ZEPHYR_EXTRA_MODULES` drive-letter split

**Search keys:** `ZEPHYR_EXTRA_MODULES`, `C:, given in ZEPHYR_EXTRA_MODULES`, `is not a valid zephyr module`,
`west build`, CMake

**Symptom:** CMake error: `C:, given in ZEPHYR_EXTRA_MODULES, is not a valid zephyr module`
(or similar split-path failure on Windows).

**Root cause:** Unquoted `-DZEPHYR_EXTRA_MODULES=C:/...` is parsed as two arguments (`C:` and
`/...`).

**Fix:** Quote the define for west/CMake, e.g.
`" -DZEPHYR_EXTRA_MODULES=C:/path/to/esp-provisioning "` (see [component.md](component.md)
for `EXTRA_ZEPHYR_MODULES` / `ZEPHYR_EXTRA_MODULES` notes).

---

### `esp-provisioning` breaks unrelated Zephyr test/sample builds (no transport selected)

**Search keys:** `BUILD_ASSERT`, `At least one provisioning transport must be enabled`,
`CONFIG_ESP_PROV_USE_BLE`, `CONFIG_ESP_PROV_USE_SOFTAP`, `twister`, `tests/net/dhcpv4/server`,
`esp_prov_internal.h`, `esp_prov_ble.c`, `esp_prov_pb.c`, `zephyr_library_sources`,
`scan_event_cb`, `'struct net_mgmt_event_callback' has no member named 'info'`

**Symptom:** Running `twister` (or `west build`) for any Zephyr-tree test or sample in this
workspace that does **not** opt into provisioning explodes with errors from this module, e.g.

- `static assertion failed: "At least one provisioning transport must be enabled
  (CONFIG_ESP_PROV_USE_BLE and/or CONFIG_ESP_PROV_USE_SOFTAP)"` (from `esp_prov_internal.h`).
- Build errors inside `esp_prov_shared.c` referring to legacy / unrelated APIs
  (`struct net_mgmt_event_callback ... 'info'`, unused `scan_event_cb`, etc.) because the
  source files compile in a kernel/networking context that doesn't match this module's
  assumptions.

**Root cause:** [`zephyr/CMakeLists.txt`](../zephyr/CMakeLists.txt) used to unconditionally
register a `zephyr_library()` and feed all `src/esp_prov_*.c` into it via
`zephyr_library_sources(...)`. Because **`ESP_PROVISIONING` is `default y`**
([`zephyr/Kconfig`](../zephyr/Kconfig)), any build in this workspace pulled the sources in.
The `BUILD_ASSERT` in `esp_prov_internal.h` then requires at least one transport
(`ESP_PROV_USE_BLE` or `ESP_PROV_USE_SOFTAP`), and those depend on `BT`/`WIFI` Kconfigs that
unrelated tests/samples don't enable — so the module trips its own guard for builds that have
no intent to provision.

**Fix:** Wrap the entire `zephyr_library*` block in `zephyr/CMakeLists.txt` with

```cmake
if(CONFIG_ESP_PROVISIONING AND
   (CONFIG_ESP_PROV_USE_BLE OR CONFIG_ESP_PROV_USE_SOFTAP))
  zephyr_library()
  ...
endif()
```

so the module becomes a true no-op when no transport is selected. Apps that intentionally use
provisioning still compile (the `BUILD_ASSERT` in `esp_prov_internal.h` remains the guard for
that case). Relevant when this module is listed in a West manifest and picked up by builds
that do not enable `CONFIG_ESP_PROVISIONING` / a transport.

---

## Logging / diagnostics

### No useful `LOG_*` output from `esp_prov_*` modules

**Search keys:** `CONFIG_LOG_MAX_LEVEL`, `CONFIG_ESP_PROV_LOG_LEVEL`, `CONFIG_LOG_DEFAULT_LEVEL`,
`CONFIG_LOG_MODE_IMMEDIATE`, `esp_prov_session`, `esp_prov_softap`, `esp_prov_ble`, `esp_prov_pkt`,
`printk`, `LOG_ERR`

**Symptom:** Provisioning appears “silent”: no `LOG_INF` / `LOG_WRN` / session traces from
`esp_prov_*`, or errors only visible via `printk` while normal logs are stripped. Alternatively
logs are too noisy for production.

**Root cause:**

1. **`CONFIG_LOG_MAX_LEVEL`** gates **compile-time** inclusion of `LOG_*` macros. If it is
   lower than **`CONFIG_ESP_PROV_LOG_LEVEL`**, module logs at higher levels are compiled out.
2. Using **`printk`** for failures bypasses the module log level system — it neither respects
   `CONFIG_ESP_PROV_LOG_LEVEL` nor disappears when you lower `LOG_MAX_LEVEL`.

**Fix:**

- Set **`CONFIG_ESP_PROV_LOG_LEVEL`** (0=off..4=debug) for the module domains
  (`esp_prov_session`, `esp_prov_softap`, `esp_prov_ble`, `esp_prov_pkt`).
- Keep **`CONFIG_LOG_MAX_LEVEL` >= `CONFIG_ESP_PROV_LOG_LEVEL`** so those lines can compile.
- Prefer **`LOG_ERR` / `LOG_WRN` / `LOG_INF`** in app code so verbosity follows Kconfig.
- **First-level diagnosis (shell sample):** `CONFIG_LOG_MAX_LEVEL=3`,
  `CONFIG_ESP_PROV_LOG_LEVEL=3` (INFO), `CONFIG_LOG_DEFAULT_LEVEL=2`,
  `CONFIG_LOG_MODE_IMMEDIATE=y` so UART sees lines without waiting on deferred flush; revert
  for production / quiet CI. Reference: [samples/esp_provisioning_shell/prj.conf](../samples/esp_provisioning_shell/prj.conf).

---

### esp32s3_devkitc shell sample silent on native USB port (console pinned to UART0)

**Search keys:** `esp32s3_devkitc`, `usb_serial`, `USB-Serial-JTAG`, `zephyr,console`,
`zephyr,shell-uart`, `CONFIG_UART_CONSOLE`, `console_getchar`, native USB, no console output,
`esp_provisioning_shell` silent

**Symptom:** `esp_provisioning_shell` flashes successfully on `esp32s3_devkitc/esp32s3/procpu`
but the menu (`printk` + `console_getchar` from [src/main.c](../samples/esp_provisioning_shell/src/main.c))
never appears on the host serial terminal when the cable is plugged into the **native USB**
connector on the devkit (the one labelled `USB`).

**Root cause:** Not Kconfig. The board DTS
[`boards/espressif/esp32s3_devkitc/esp32s3_devkitc_procpu.dts`](../../zephyr/boards/espressif/esp32s3_devkitc/esp32s3_devkitc_procpu.dts)
pins `chosen { zephyr,console = &uart0; zephyr,shell-uart = &uart0; }` and explicitly
`status = "disabled"` on `&usb_serial` (the ESP32-S3 USB-Serial-JTAG controller). UART0 on
this devkit is wired to the **CP210x/CH343 USB-UART bridge** chip — i.e. the connector
labelled `UART`, not the native USB connector. `CONFIG_UART_CONSOLE=y` only selects "use the
chosen UART for console"; it does not change which physical port the chosen node points to.

**Fix:** Add a per-board overlay (auto-picked-up by Zephyr for this board target) that
re-points `zephyr,console` / `zephyr,shell-uart` to `&usb_serial` and enables it. UART0 stays
enabled so esptool / ROM-bootloader flashing over the UART bridge port still works:

```dts
/ {
	chosen {
		zephyr,console = &usb_serial;
		zephyr,shell-uart = &usb_serial;
	};
};

&usb_serial {
	status = "okay";
};
```

Reference file:
[`samples/esp_provisioning_shell/boards/esp32s3_devkitc_procpu.overlay`](../samples/esp_provisioning_shell/boards/esp32s3_devkitc_procpu.overlay).
Kept developer-local via [`.gitignore`](../.gitignore) so the sample's default config still
matches the upstream board DTS (UART bridge port = console). Drop the gitignore line to share
the overlay.

After the overlay, `build/zephyr/.config` shows the same `CONFIG_UART_CONSOLE=y` /
`CONFIG_CONSOLE_SUBSYS=y` / `CONFIG_CONSOLE_GETCHAR=y` as before — only the chosen DT node
changes; no Kconfig edit is needed in `prj.conf`.

Same story on other ESP32-S3 boards whose DTS keeps `&usb_serial` disabled and `zephyr,console = &uart0`
(e.g. `esp_threadbr`); the per-board overlay name just changes.

---

## Transport prerequisites

### Build fails: at least one transport must be enabled (`BUILD_ASSERT`)

**Search keys:** `BUILD_ASSERT`, `At least one provisioning transport`, `CONFIG_ESP_PROV_USE_BLE`,
`CONFIG_ESP_PROV_USE_SOFTAP`

**Symptom:** Build fails with a static assert about transports.

**Root cause:** Both `CONFIG_ESP_PROV_USE_BLE` and `CONFIG_ESP_PROV_USE_SOFTAP` were disabled.

**Fix:** Enable at least one transport. Enforced by `BUILD_ASSERT` in
[src/esp_prov_internal.h](../src/esp_prov_internal.h).

---

## SoftAP transport (HTTP / DNS / DHCP)

### Captive-portal probes dominate early traffic

**Search keys:** `generate_204`, `:443`, `DNS`, `proto-ver`, captive, connectivity

**Symptom:** Phone connects to the SoftAP; you see DNS traffic and/or TCP probes on `:443`, but
the provisioning app never reaches `/proto-ver` on `:80`.

**Root cause:** Captive-portal detection can run before the provisioning app and may prefer
`HTTPS :443` probes to well-known names, even on an isolated SoftAP.

**Fix:** Ensure DHCP provides DNS pointing at the SoftAP gateway, and ensure the HTTP server
responds to captive probe paths (e.g. `/generate_204`) with `HTTP/1.0 204` so the OS keeps
traffic on the SoftAP. See the SoftAP checklist in [component.md](component.md) and
[src/esp_prov_run.c](../src/esp_prov_run.c).

---

### Phone VPN active — SoftAP provisioning fails or never reaches device

**Search keys:** `VPN`, `WireGuard`, `OpenVPN`, `always-on VPN`, `private relay`, SoftAP,
`proto-ver`, phone connects, ESP BLE Provisioning

**Symptom:** Device logs look healthy (SoftAP up, DHCP, DNS, HTTP listen, maybe captive probes),
but the phone never completes provisioning over **SoftAP** — app stuck, no `/proto-ver`, or the
phone drops the AP quickly. **BLE** provisioning may still work on the same firmware.

**Root cause:** An active **VPN** (or similar always-on tunnel / “block connections without VPN”)
on the phone can steal the default route, block or deprioritize traffic to the isolated
provisioning AP, or prevent the OS from routing the provisioning app over the SoftAP interface.
The device stack is often fine; the phone does not send (or keep) provisioning traffic on the AP.

**Fix:** **Disable VPN** (and similar tunnel apps) for the provisioning session, then retry SoftAP.
If VPN cannot be turned off, use **BLE** when `CONFIG_ESP_PROV_USE_BLE` is enabled. When
debugging “everything should work”: confirm whether VPN was on — add to operator test checklists.

---

### SoftAP bring-up crashes when scanning runs before AP enable

**Search keys:** `NET_REQUEST_WIFI_SCAN`, `esp_wifi_start`, SoftAP, scan, AP enable

**Symptom:** SoftAP bring-up crashes or becomes unstable when scanning is started too early.

**Root cause:** Some Wi‑Fi drivers call start/stop internally during scan; scanning before the
AP is enabled can race AP start.

**Fix:** Bring up SoftAP first, then scan (or scan on-demand). See the checklist in
[component.md](component.md).

---

### `AP IPv4/DHCP setup failed` when STA is associated (single-mode build)

**Date:** 2026-05-18

**Search keys:** `AP IPv4/DHCP setup failed`, `Provisioning failed: 4`, `enable_dhcp_and_ip`,
`net_if_ipv4_addr_add`, `CONFIG_ESP32_WIFI_AP_STA_MODE`, `NET_REQUEST_WIFI_AP_ENABLE`,
`NET_REQUEST_WIFI_DISCONNECT`, single-mode, STA associated, re-provision, stored credentials,
`wifi_credentials` auto-connect

**Symptom:** A second/subsequent `esp_prov_run()` (option 1 in the shell sample) fails
immediately with:

```
[…] <err> esp_prov_softap: AP IPv4/DHCP setup failed
[…] <err> esp_prov_session: Provisioning failed: 4
Provisioning failed: 4
```

Reliably reproduced when stored Wi-Fi credentials cause the STA to be associated **before**
provisioning is invoked (e.g. after a reboot, or after the previous session's test-join).
First-boot provisioning works because STA is `STOPPED/STARTED`, not associated.

**Root cause:** With `CONFIG_ESP32_WIFI_AP_STA_MODE=n` (legacy shell default; still valid for
minimal single-iface builds), the Wi-Fi driver runs in a
single mode at a time and there is effectively **one** Zephyr wifi net_if. Once STA has
associated, that iface already carries the STA IPv4 (e.g. `192.168.1.127`) plus the leftover
SoftAP gateway (`192.168.4.1`) from earlier sessions. When `esp_prov_run()` calls
`enable_dhcp_and_ip()` on `net_if_get_wifi_sap()`, `net_if_ipv4_addr_add(s_ap,
192.168.4.1, NET_ADDR_MANUAL, 0)` returns `NULL` (duplicate address / iface state), the
function bails with `-EIO`, the SoftAP HTTP/DNS path never starts, and the session aborts.

**Fix:** Application-side. Before invoking `esp_prov_run()`, the sample tears down STA if
it's busy (`WIFI_STATE_SCANNING` … `WIFI_STATE_COMPLETED`, including the ESP32 driver's
`CONNECTING → SCANNING` collapse — see the EALREADY entry above):

```c
struct net_if *sta = net_if_get_wifi_sta();
struct wifi_iface_status iface_st = { 0 };

if (sta &&
    net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, sta, &iface_st, sizeof(iface_st)) == 0 &&
    iface_st.state >= WIFI_STATE_SCANNING) {
        (void)net_mgmt(NET_REQUEST_WIFI_DISCONNECT, sta, NULL, 0);
        k_sleep(K_MSEC(500));   /* let driver leave CONNECTED/CONNECTING */
}
```

This belongs in the **app**, not `esp_prov_run()`: the module requires a clean slate before
SoftAP bring-up; only the application knows whether disconnecting STA is acceptable (e.g.
operator re-provision vs. background STA that must stay up). Enable APSTA or disconnect STA
first — see fix above and shell `option_provisioning()`.

Reference: [samples/esp_provisioning_shell/src/main.c](../samples/esp_provisioning_shell/src/main.c)
`option_provisioning()`. Concurrent-mode alternative: enable **`CONFIG_ESP32_WIFI_AP_STA_MODE=y`**
(see [samples/esp_provisioning_shell/prj.conf](../samples/esp_provisioning_shell/prj.conf) and
the APSTA notes in [component.md](component.md)) so STA and SoftAP use separate `net_if`s and
this collision goes away.

---

### TCP context exhaustion under probe bursts (`net_context_get(): -2`)

**Search keys:** `net_context_get()`, `-2`, `ENOENT`, `Cannot allocate a new TCP connection`,
`CONFIG_NET_MAX_CONTEXTS`, `net_tcp`

**Symptom:** Logs show TCP context allocation failures (for example `net_context_get()`
failures) during heavy captive-portal probing.

**Root cause:** The phone may open many short-lived connections; if `CONFIG_NET_MAX_CONTEXTS`
is too low, new sockets can fail.

**Fix:** Increase `CONFIG_NET_MAX_CONTEXTS` and ensure probe sockets are closed promptly in
the application/module integration ([src/esp_prov_run.c](../src/esp_prov_run.c)).

---

## BLE transport (GATT)

### GATT caching / DB-hash mismatch

**Search keys:** `CONFIG_BT_GATT_CACHING`, `DB_OUT_OF_SYNC`, GATT cache, DB hash

**Symptom:** BLE connects, but GATT reads/writes fail or the client disconnects early without
the expected provisioning traffic.

**Root cause:** Robust caching (GATT caching) can cause `DB_OUT_OF_SYNC` behavior unless the
client implements the DB hash handshake and service-changed behavior correctly.

**Fix:** If needed for your environment, disable caching in the consuming app:
`CONFIG_BT_GATT_CACHING=n`.

---

### BLE connect -> `EXCCAUSE` illegal instruction in `z_swap` (BT RX stack overflow)

**Search keys:** `EXCCAUSE`, `z_swap`, `Current thread: (unknown)`, `Current thread: unknown`,
`BT_RX_STACK_SIZE`, `bt_gatt_notify`, `ble_connected`, `__l_vfprintf`, `EXCCAUSE 28`

**Symptom:** Log shows `BLE provisioning peer connected`, then `EXCCAUSE` illegal instruction;
`addr2line` on PC often lands in `z_swap` / `Current thread: (unknown)`. Sometimes surfaces
as `EXCCAUSE 28` in `__l_vfprintf` on whatever thread runs next after a DNS/probe burst — still
often stack corruption from the same root cause.

**Root cause:** `ble_connected` and GATT write handlers run on the **BT RX thread** (default
`CONFIG_BT_RX_STACK_SIZE` 1200 B). SoftAP + immediate logging + `bt_gatt_notify` stack, and
later sec1 mbedTLS on the same thread, can **overflow** that stack and corrupt kernel/thread
state.

**Fix:** In the consuming app set **`CONFIG_BT_RX_STACK_SIZE=4096`** (see
[samples/esp_provisioning_shell/prj.conf](../samples/esp_provisioning_shell/prj.conf)).
Defer the initial proto-ver `bt_gatt_notify` to the **system workqueue** (`k_work_submit`) so
the connect callback stays shallow ([src/esp_prov_ble.c](../src/esp_prov_ble.c)).

---

## sec1 / PoP

### PoP mismatch

**Search keys:** `CONFIG_ESP_PROV_POP`, `PoP`, proof-of-possession, QR, sec1 handshake

**Symptom:** The phone app connects but sec1 handshake fails; provisioning never reaches Wi‑Fi
config messages.

**Root cause:** `CONFIG_ESP_PROV_POP` differs between device and app/QR payload.

**Fix:** Ensure PoP matches exactly (including case), and ensure QR payload uses the same PoP.

---

### Entropy / CTR-DRBG seed failures under load

**Search keys:** `MBEDTLS_ERR_ENTROPY`, `-52`, `MBEDTLS_ERR_ENTROPY_SOURCE_FAILED`,
`esp_prov_sec1_rng_prewarm`, `mbedtls_entropy_func`

**Symptom:** sec1 handshake fails early with entropy/DRBG errors.

**Root cause:** Entropy collection and DRBG seeding can be sensitive to timing and system load.

**Fix:** Prefer prewarming RNG before heavy RF activity (`esp_prov_sec1_rng_prewarm()` in
[src/esp_prov_internal.h](../src/esp_prov_internal.h)), and keep BT RX stack and logging
configured so sec1 can run without stack overflow.

---

### TF-PSA 1.0 (Zephyr 4.4): legacy `mbedtls_entropy_*` not linked

**Search keys:** `mbedtls_entropy_init`, `mbedtls_ctr_drbg`, `TF-PSA`, `psa_crypto_init`,
`psa_generate_random`, `CONFIG_MBEDTLS_ENTROPY_C`

**Symptom:** Linker undefined references to `mbedtls_entropy_init` / CTR‑DRBG helpers from
`esp_prov_sec1.c`, even when `CONFIG_MBEDTLS_ENTROPY_C=y`.

**Root cause:** TF‑PSA Crypto treats legacy entropy as removed/stubbed; the translation unit can
compile with no callable implementations, so symbols never appear in `libmbedcrypto`.

**Fix:** `esp_prov_sec1` seeds random bytes via **`psa_crypto_init()`** and
**`psa_generate_random()`** (PSA RNG). The shell sample `prj.conf` omits `CONFIG_MBEDTLS_ENTROPY_C`
and `CONFIG_MBEDTLS_CTR_DRBG_C`; keep **`CONFIG_PSA_WANT_*`** aligned with sec1 (see next entry).
See [src/esp_prov_sec1.c](../src/esp_prov_sec1.c).

---

### sec1 X25519: undefined `mbedtls_ecp_*` / `mbedtls_mpi_*` (`PSA_WANT_ECC_MONTGOMERY_255`)

**Search keys:** `mbedtls_ecp_`, `mbedtls_mpi_`, `CURVE25519`, `MBEDTLS_ECP_DP_CURVE25519`,
`CONFIG_PSA_WANT_ECC_MONTGOMERY_255`, `removed/ecdh.c`

**Symptom:** Undefined references to `mbedtls_ecp_*`, `mbedtls_mpi_*`, and hostap `removed/ecdh.c`
helpers when linking.

**Root cause:** Without Montgomery curve PSA wants, TF‑PSA **builtin** `ecp.c` does not enable
Curve25519 (`MBEDTLS_ECP_DP_CURVE25519_ENABLED`), so legacy ECDH code has nothing to link.

**Fix:** Set **`CONFIG_PSA_WANT_ECC_MONTGOMERY_255=y`** (see
[samples/esp_provisioning_shell/prj.conf](../samples/esp_provisioning_shell/prj.conf)).

---

## API / integration

### Post-provision: credentials / STA (app wraps `esp_prov_run()`)

**Search keys:** `esp_prov_run`, `wifi_credentials`, `STA`, persistence, `esp_wifi_credentials`,
`NET_REQUEST_WIFI_CONNECT`, `esp_prov_run_logged`, `ESP_PROV_BUILTIN_SESSION`

**Symptom:** After `esp_prov_run()` succeeds, the app must save SSID/PSK and/or bring up STA,
but nothing in the module does that automatically.

**Root cause:** `esp_prov_run()` returns credentials only; it does not persist to NVS or join
STA. Session start/outcome logs come from `esp_prov_session` inside
[prov_controller.c](../src/prov_controller.c). Legacy **`esp_prov_run_logged()`** and
**`CONFIG_ESP_PROV_BUILTIN_SESSION`** were removed — one public API only.

**Fix:** In the consuming application, wrap `esp_prov_run(&creds)` with your policy: e.g.
`wifi_credentials` + `NET_REQUEST_WIFI_CONNECT`, deferred workqueue join, factory reset, etc.
The shell sample menu (options 2–4) is a minimal reference for test-join and NVS save — see
[samples/esp_provisioning_shell/src/main.c](../samples/esp_provisioning_shell/src/main.c).
Keep app-specific logging in the app layer, not in this module.

---

## Shell sample (`esp_provisioning_shell`)

Reference integration only — see [samples/esp_provisioning_shell/README.md](../samples/esp_provisioning_shell/README.md).

### Shell sample: SoftAP missing with AP_STA off or wrong net Kconfig

**Search keys:** `esp_provisioning_shell`, `CONFIG_ESP32_WIFI_AP_STA_MODE`, `AP IPv4/DHCP setup failed`,
`net_if_get_wifi_sap`, single net_if, BLE only on boot

**Symptom:** Shell sample shows **BLE only** on boot or SoftAP never works (no `PROV_*` AP,
`AP IPv4/DHCP setup failed`, option 1 fails) despite intending both transports.

**Root cause:** **`CONFIG_ESP32_WIFI_AP_STA_MODE=n`** makes STA and SoftAP share one `net_if`.
Missing SoftAP-oriented DHCP/net options (ICMP probe timeout, DNS option, interface names) breaks
phone DHCP on ESP32.

**Fix:** Use current [`samples/esp_provisioning_shell/prj.conf`](../samples/esp_provisioning_shell/prj.conf)
defaults (`AP_STA_MODE=y`, `app.overlay`). For one transport only, merge
[`overlay-ble-only.conf`](../samples/esp_provisioning_shell/overlay-ble-only.conf) or
[`overlay-softap-only.conf`](../samples/esp_provisioning_shell/overlay-softap-only.conf).

---

### Shell sample option 2: dangling stack pointers when joining from stored credentials

**Date:** 2026-05-18

**Search keys:** `option_test_wifi`, `resolve_connect_params`, `fill_connect_from_stored_personal`,
`wifi_credentials_personal`, `wifi_connect_req_params`, `NET_REQUEST_WIFI_CONNECT`,
`esp32_wifi_connect`, dangling pointer, stored credentials, option 2 silent, after reboot

**Symptom:** In [samples/esp_provisioning_shell/src/main.c](../samples/esp_provisioning_shell/src/main.c)
option **2 (Test WiFi connection)** appears to do nothing after a reboot when credentials only
exist in NVS (no fresh provisioning in RAM): no `WiFi connected` and usually no
`WiFi connect failed (status=…)` either — the join is issued against garbage. The same
flow works when `last_prov_ok == true` (joining directly after a successful option 1) because
that path uses `static struct esp_wifi_credentials last_creds`.

**Root cause:** `resolve_connect_params()` declared `struct wifi_credentials_personal cp;` on
its **own** stack and then called `fill_connect_from_stored_personal(&cp, params)`, which
stores `params->ssid = cp.header.ssid` and `params->psk = cp.password` — pointers into `cp`.
When `resolve_connect_params()` returns, `cp`'s stack frame is reclaimed; the immediately
following locals in `wifi_do_connect()` (`sta`, `ret`, `deadline`) and the `net_mgmt` call
chain reuse that memory before the Wi-Fi driver dereferences the pointers. The ESP32 driver
([drivers/wifi/esp32/src/esp_wifi_drv.c](../../zephyr/drivers/wifi/esp32/src/esp_wifi_drv.c)
`esp32_wifi_connect`) does `memcpy(wifi_config.sta.ssid, params->ssid, params->ssid_length)`
**inside** the handler, so by then `params->ssid` already points to overwritten stack bytes
→ join request with junk SSID/PSK → silent failure or timeout. The `last_prov_ok` path is
unaffected only because `last_creds` is file-scope static.

**Fix:** Hoist the credentials buffer to the caller so it outlives the connect call. The
resolver now takes the storage as an out parameter; `option_test_wifi()` keeps the struct on
its own stack which is alive across `wifi_do_connect()`:

```c
static int resolve_connect_params(struct wifi_connect_req_params *params,
				  struct wifi_credentials_personal *cp_buf);

static void option_test_wifi(void)
{
	struct wifi_connect_req_params params;
	struct wifi_credentials_personal cp;	/* must outlive NET_REQUEST_WIFI_CONNECT */
	int ret;

	ret = resolve_connect_params(&params, &cp);
	...
	ret = wifi_do_connect(&params);
	...
}
```

**General rule:** `struct wifi_connect_req_params` is **pointer-based by design**
(`const uint8_t *ssid`, `const uint8_t *psk`). The caller must keep those buffers alive
**at least until `net_mgmt(NET_REQUEST_WIFI_CONNECT, …)` returns** — i.e. until the chosen
driver's `connect` op has copied them. Static / file-scope buffers or caller-frame buffers
both work; resolver-frame buffers do not.

---

### Shell sample option 2: `NET_REQUEST_WIFI_CONNECT failed: -120` (`-EALREADY`)

**Date:** 2026-05-18

**Search keys:** `NET_REQUEST_WIFI_CONNECT failed: -120`, `-EALREADY`, `EALREADY`, `option 2`,
`esp32_wifi_connect`, `ESP32_STA_CONNECTING`, `ESP32_STA_CONNECTED`, `CONFIG_ESP32_WIFI_STA_RECONNECT`,
`wifi_mgmt_raise_connect_result_event`, `WIFI_STATUS_CONN_FAIL`, `NET_REQUEST_WIFI_IFACE_STATUS`,
`wifi_state_txt`, `WIFI_STATE_COMPLETED`

**Symptom:** Option 2 ("Test WiFi connection") prints:

```
NET_REQUEST_WIFI_CONNECT failed: -120
Connect failed: -120
```

…even with valid (stored or freshly provisioned) credentials. Most commonly seen when option 2
is pressed shortly **after option 1** in the same session.

**Root cause:** `-120` is `-EALREADY` (`zephyr/lib/libc/minimal/include/errno.h`). It is
returned by the very first guard in
[drivers/wifi/esp32/src/esp_wifi_drv.c](../../zephyr/drivers/wifi/esp32/src/esp_wifi_drv.c)
`esp32_wifi_connect()`:

```c
if (data->state == ESP32_STA_CONNECTING || data->state == ESP32_STA_CONNECTED) {
    wifi_mgmt_raise_connect_result_event(iface, WIFI_STATUS_CONN_FAIL);
    return -EALREADY;
}
```

Two ways `data->state` is "already busy" without the app having called
`NET_REQUEST_WIFI_CONNECT` itself:

1. **Provisioning test-join.** The Espressif provisioning protocol issues an STA connect from
   inside `esp_prov_run()` to verify the SSID/PSK the phone just sent. When `esp_prov_run()`
   returns the link is typically `CONNECTING`/`CONNECTED`, so re-issuing a connect from
   `option_test_wifi()` immediately hits the guard.
2. **`CONFIG_ESP32_WIFI_STA_RECONNECT=y`.** The driver's
   `esp_wifi_handle_sta_disconnect_event()` calls `esp_wifi_connect()` and sets state to
   `ESP32_STA_CONNECTING` on any unsolicited disconnect (except `WIFI_REASON_ASSOC_LEAVE`),
   keeping the link in `CONNECTING` indefinitely from the app's point of view.

`wifi_mgmt_raise_connect_result_event(iface, WIFI_STATUS_CONN_FAIL)` is also fired
**synchronously** for the rejected request, so a naive `wifi_do_connect()` that only watches
the `NET_EVENT_WIFI_CONNECT_RESULT` callback would see a (spurious) `WIFI_STATUS_CONN_FAIL`
and double-report a failure that is not actually our request's failure.

**Fix:** In [src/main.c](../samples/esp_provisioning_shell/src/main.c) make option 2
idempotent:

- Query `NET_REQUEST_WIFI_IFACE_STATUS` first. If `iface_st.state >= WIFI_STATE_SCANNING`
  (covers SCANNING / AUTHENTICATING / ASSOCIATING / ASSOCIATED / 4WAY_HANDSHAKE /
  GROUP_HANDSHAKE / COMPLETED — strict-order enum, see `wifi.h` `BUILD_ASSERT`), **do not**
  issue a new `NET_REQUEST_WIFI_CONNECT`. Instead poll `iface_st.state` until
  `WIFI_STATE_COMPLETED` / `WIFI_STATE_DISCONNECTED` / timeout, then print SSID + IPv4 via
  `print_sta_ipv4_info()`.
- **`WIFI_STATE_SCANNING`, not `_AUTHENTICATING`, is the right threshold on ESP32** because
  `esp32_wifi_status()` in
  [drivers/wifi/esp32/src/esp_wifi_drv.c](../../zephyr/drivers/wifi/esp32/src/esp_wifi_drv.c)
  collapses its internal `ESP32_STA_CONNECTING` into `WIFI_STATE_SCANNING`, and that is
  exactly the state that triggers `-EALREADY` from `esp32_wifi_connect()`. A threshold of
  `>= WIFI_STATE_AUTHENTICATING` silently misses the `CONNECTING` case and the app still
  prints the original `-EALREADY` error.
- Handle the residual race in `wifi_do_connect()`: if `net_mgmt(NET_REQUEST_WIFI_CONNECT, …)`
  returns `-EALREADY`, do **not** wait for the connect-result callback (the driver already
  raised a synthetic `WIFI_STATUS_CONN_FAIL` for the rejected request, which would lie about
  the link state). Return `-EALREADY`, and let `option_test_wifi()` fall back to the
  poll-iface-status path.

The poll helper uses `wifi_state_txt()` for human-readable state names. No Kconfig changes.

**Generalises to:** Any Zephyr app on the ESP32 family that issues `NET_REQUEST_WIFI_CONNECT`
explicitly while `CONFIG_ESP32_WIFI_STA_RECONNECT=y` or after using a higher-level connection
manager / provisioning module that joins on its own. Either gate the connect on iface status
or treat `-EALREADY` as "join in progress, observe via iface status / connectivity events".

---

## `esp_prov_bt_enable()` is not public API

**Search keys:** `esp_prov_bt_enable`, undefined reference `esp_prov_bt_enable`, BLE before provisioning

**Context:** BLE controller bring-up (`bt_enable()`, settings, TX power) is OS infrastructure; it does not belong on the optional provisioning module’s public surface.

**Direction:** Use only [`esp_prov_run()`](../src/esp_prov.h) from application code. When `CONFIG_ESP_PROV_USE_BLE` is set, `esp_prov_run()` calls internal `esp_prov_bt_enable()` before starting GATT. If the product uses other BLE roles in the same boot **before** the first `esp_prov_run()`, the app must call Zephyr `bt_enable()` (and its bonding/settings policy) itself — see [component.md](component.md) runtime architecture.

---

## Cancel API: immediate, no module debounce or GPIO

**Search keys:** `esp_prov_cancel`, `esp_prov_cancel_isr`, `esp_prov_user_cancel_may_run`,
`CONFIG_ESP_PROV_USER_CANCEL_COOLDOWN_MS`, cancel ignored during bring-up, GPIO debounce,
duplicate ISR cancel

**Symptom:** Older builds exposed `esp_prov_user_cancel_may_run()`, gated cancel until
“session ready”, and offered `CONFIG_ESP_PROV_USER_CANCEL_COOLDOWN_MS` — implying the
module owned button/GPIO timing.

**Root cause:** Provisioning is a protocol/session component, not an input or UX layer.
Debouncing, bring-up windows, and what hardware may abort a session are product decisions.

**Fix / policy (current):**

- Public API: `esp_prov_cancel()` (thread) and `esp_prov_cancel_isr()` (ISR-safe path only).
  Each call **always** requests stop immediately; the module does not track prior calls or
  caller identity.
- No GPIO, buttons, or debounce in this module — not in API, Kconfig, or docs.
- Removed: `esp_prov_user_cancel_may_run()`, `CONFIG_ESP_PROV_USER_CANCEL_COOLDOWN_MS`,
  bring-up/cooldown gates on cancel.
- Module-initiated aborts (wall-clock timeout, BLE idle after disconnect) use internal
  `esp_prov_cancel_system()` — same teardown path, not a separate “policy” for the app.

**Direction for apps:** Filter in the application if needed (debounce, ignore IRQ while not
in provisioning, ignore duplicate edges). When you want to abort, call cancel once; handle
`ESP_PROV_ERR_CANCELLED` from `esp_prov_run()`. Spec: [component.md](component.md) public API.

---
