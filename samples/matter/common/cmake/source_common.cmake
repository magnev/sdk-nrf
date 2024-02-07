#
# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

set(MATTER_COMMONS_SRC_DIR ${ZEPHYR_NRF_MODULE_DIR}/samples/matter/common/src)

target_include_directories(app PRIVATE
    ${MATTER_COMMONS_SRC_DIR}
)

# Set sources that are used by all samples
target_sources(app PRIVATE
    ${MATTER_COMMONS_SRC_DIR}/board/led_widget.cpp
    ${MATTER_COMMONS_SRC_DIR}/board/board.cpp
    ${MATTER_COMMONS_SRC_DIR}/app/task_executor.cpp
    ${MATTER_COMMONS_SRC_DIR}/app/matter_init.cpp
    ${MATTER_COMMONS_SRC_DIR}/app/matter_event_handler.cpp
)

# Set specific sources that depend on Kconfigs
if(CONFIG_CHIP_OTA_REQUESTOR OR CONFIG_MCUMGR_TRANSPORT_BT)
    target_sources(app PRIVATE ${MATTER_COMMONS_SRC_DIR}/dfu/ota/ota_util.cpp)
endif()

if(CONFIG_PWM)
    target_sources(app PRIVATE ${MATTER_COMMONS_SRC_DIR}/pwm/pwm_device.cpp)
endif()

if(CONFIG_MCUMGR_TRANSPORT_BT)
    zephyr_library_link_libraries(MCUBOOT_BOOTUTIL)
    target_sources(app PRIVATE ${MATTER_COMMONS_SRC_DIR}/dfu/smp/dfu_over_smp.cpp)
endif()

if(CONFIG_NCS_SAMPLE_MATTER_OPERATIONAL_KEYS_MIGRATION_TO_ITS)
    target_sources(app PRIVATE ${MATTER_COMMONS_SRC_DIR}/migration/migration_manager.cpp)
endif()

if(CONFIG_CHIP_NUS)
    target_sources(app PRIVATE ${MATTER_COMMONS_SRC_DIR}/bt_nus/bt_nus_service.cpp)
endif()
