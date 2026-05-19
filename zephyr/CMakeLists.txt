# SPDX-License-Identifier: Apache-2.0

# Only compile the module when the consuming app has opted in to
# esp_provisioning AND selected at least one transport. Otherwise the module
# is a no-op: this avoids tripping esp_prov_internal.h's BUILD_ASSERT (which
# requires a transport) and dangling zephyr_library_* calls in unrelated
# Zephyr tests/samples built in this workspace that do not enable
# CONFIG_ESP_PROVISIONING.
if(CONFIG_ESP_PROVISIONING AND
   (CONFIG_ESP_PROV_USE_BLE OR CONFIG_ESP_PROV_USE_SOFTAP))

  zephyr_library()

  zephyr_library_include_directories(${CMAKE_CURRENT_LIST_DIR}/../src)

  zephyr_library_sources(
    ${CMAKE_CURRENT_LIST_DIR}/../src/esp_prov_ble.c
    ${CMAKE_CURRENT_LIST_DIR}/../src/esp_prov_pb.c
    ${CMAKE_CURRENT_LIST_DIR}/../src/esp_prov_run.c
    ${CMAKE_CURRENT_LIST_DIR}/../src/esp_prov_sec1.c
    ${CMAKE_CURRENT_LIST_DIR}/../src/esp_prov_shared.c
    ${CMAKE_CURRENT_LIST_DIR}/../src/esp_prov_trace.c
    ${CMAKE_CURRENT_LIST_DIR}/../src/prov_controller.c
  )

  if(CONFIG_MBEDTLS)
    zephyr_library_link_libraries(mbedTLS)
    zephyr_library_include_directories(${CMAKE_BINARY_DIR}/legacy-mbedtls-headers)
    if(DEFINED ZEPHYR_HOSTAP_MODULE_DIR)
      zephyr_library_include_directories(${ZEPHYR_HOSTAP_MODULE_DIR}/port/mbedtls/removed)
    endif()
  endif()

  # sec1 uses mbedtls/ecdh.h + mbedtls_ecdh_* from TF-PSA "removed" compat layer
  # (see zephyr/modules/mbedtls/legacy_support.cmake). On SoCs where neither
  # CONFIG_ESP32_WIFI_MBEDTLS_CRYPTO nor ESP32_BT_LE_CRYPTO_STACK_MBEDTLS applies,
  # pull in the same ecdh.c + include path here.
  if(CONFIG_MBEDTLS AND CONFIG_MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS AND
     DEFINED ZEPHYR_HOSTAP_MODULE_DIR)
    if(TARGET mbedTLS AND TARGET builtin AND NOT CONFIG_ESP32_WIFI_MBEDTLS_CRYPTO AND
        NOT CONFIG_ESP32_BT_LE_CRYPTO_STACK_MBEDTLS)
      target_include_directories(mbedTLS INTERFACE ${ZEPHYR_HOSTAP_MODULE_DIR}/port/mbedtls/removed)
      target_sources(builtin PRIVATE ${ZEPHYR_HOSTAP_MODULE_DIR}/port/mbedtls/removed/ecdh.c)
      target_compile_definitions(builtin PRIVATE
        TF_PSA_CRYPTO_CONFIG_CHECK_BYPASS
        MBEDTLS_ECDH_C
      )
      target_include_directories(builtin PRIVATE ${ZEPHYR_HOSTAP_MODULE_DIR}/port/mbedtls/removed)
    endif()
  endif()

endif()

