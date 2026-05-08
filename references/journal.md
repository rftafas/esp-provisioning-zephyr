# Provisioning journal (`esp_provisioning`)

Concise **Symptom / Root cause / Fix** entries for integration pitfalls when using this
module (SoftAP/BLE protocomm + sec1). This is not a product log. For west/module setup and
API overview, see [component.md](component.md).

---

## How AI / humans should read this

Each entry has **`Search keys:`** — tokens from logs, link errors, or Kconfig symbols.
**Grep this file (or the build log) for a key first**, then read that entry’s three blocks.

---

## Index

**Build / workspace**

- [Stale `zephyr_modules.txt` after `west update`](#stale-zephyr_modulestxt-after-west-update)
- [Undefined `mbedtls_ecdh_gen_public` / `mbedtls_ecdh_compute_shared` at link time](#undefined-mbedtls_ecdh_gen_public--mbedtls_ecdh_compute_shared-at-link-time)
- [Windows: `ZEPHYR_EXTRA_MODULES` drive-letter split](#windows-zephyr_extra_modules-drive-letter-split)

**Logging / diagnostics**

- [No useful `LOG_*` output from `esp_prov_*` modules](#no-useful-log_-output-from-esp_prov_-modules)

**Transport prerequisites**

- [Build fails: at least one transport must be enabled (`BUILD_ASSERT`)](#build-fails-at-least-one-transport-must-be-enabled-build_assert)

**SoftAP transport (HTTP / DNS / DHCP)**

- [Captive-portal probes dominate early traffic](#captive-portal-probes-dominate-early-traffic)
- [SoftAP bring-up crashes when scanning runs before AP enable](#softap-bring-up-crashes-when-scanning-runs-before-ap-enable)
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

### SoftAP bring-up crashes when scanning runs before AP enable

**Search keys:** `NET_REQUEST_WIFI_SCAN`, `esp_wifi_start`, SoftAP, scan, AP enable

**Symptom:** SoftAP bring-up crashes or becomes unstable when scanning is started too early.

**Root cause:** Some Wi‑Fi drivers call start/stop internally during scan; scanning before the
AP is enabled can race AP start.

**Fix:** Bring up SoftAP first, then scan (or scan on-demand). See the checklist in
[component.md](component.md).

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

### Post-provision: credentials / STA (app wraps `esp_prov_run()`)

**Search keys:** `esp_prov_run`, `wifi_credentials`, `STA`, persistence, `dualkey_esp_prov_session_run`,
`esp_prov_run_logged`, `ESP_PROV_BUILTIN_SESSION`

**Symptom:** Need to save SSID/PSK to NVS or connect STA after provisioning while keeping module generic.

**Root cause:** `esp_prov_run()` returns credentials only; the module does not persist or join STA. Session **start** / **generic outcome** logs are emitted inside `esp_prov_run()` (log module `esp_prov_session` in [prov_controller.c](../src/prov_controller.c)). The old second entry point **`esp_prov_run_logged()`** and **`CONFIG_ESP_PROV_BUILTIN_SESSION`** were removed — one public API only.

**Fix:** Implement a small app function that calls `esp_prov_run(&creds)` then runs product policy (save, deferred join, etc.). Example: **`dualkey_esp_prov_session_run()`** in the DualKey app. Product-only logs stay in that wrapper.

---
