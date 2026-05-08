# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

# This application directory lives inside the esp-provisioning repo; register the repo root
# as a Zephyr module so plain `west build -b <board> path/to/this/sample` works without
# passing -DZEPHYR_EXTRA_MODULES on the command line (still mergeable if also set by env/CLI).
get_filename_component(ESP_PROVISIONING_MODULE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
list(APPEND ZEPHYR_EXTRA_MODULES "${ESP_PROVISIONING_MODULE_DIR}")

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(esp_provisioning_shell)

target_include_directories(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src)

target_sources(app PRIVATE src/main.c)
