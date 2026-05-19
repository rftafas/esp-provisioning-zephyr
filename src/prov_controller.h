/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Provisioning session controller: wall-clock limit and join on a dedicated
 * routine thread (see references/component.md). Not a public API -- only
 * esp_prov_run() calls this.
 */

#ifndef PROV_CONTROLLER_H
#define PROV_CONTROLLER_H

#include "esp_prov.h"

/**
 * Block until the provisioning routine finishes, CONFIG_ESP_PROV_SESSION_TIMEOUT_SEC
 * elapses (then cancel + join), or the routine exits on its own.
 *
 * Start/cancel triggers are app policy; this function only enforces the session
 * wall-clock bound and maps expiry to ESP_PROV_ERR_TIMEOUT (distinct from esp_prov_cancel*).
 */
int prov_controller_run_blocking(struct esp_wifi_credentials *out);

#endif /* PROV_CONTROLLER_H */
