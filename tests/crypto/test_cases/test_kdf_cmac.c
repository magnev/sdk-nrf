/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stddef.h>
#include <logging/log.h>

#include "common_test.h"
#include <cc3xx_kmu.h>
#include <nrf_cc3xx_platform_kmu.h>
#include <nrf_cc3xx_platform_defines.h>

/* Setting LOG_LEVEL_DBG might affect time measurements! */
LOG_MODULE_REGISTER(test_kdf_cmac, LOG_LEVEL_INF);

extern test_vector_kdf_cmac_t __start_test_vector_kdf_cmac_data[];
extern test_vector_kdf_cmac_t __stop_test_vector_kdf_cmac_data[];

#define BITS_IN_BYTE 8

/* TODO: Possibly tune buffers which have lower size requirements */
#define KDF_CMAC_KI_BUF_SIZE (32)
#define KDF_CMAC_KO_BUF_SIZE (1026)
#define KDF_CMAC_LABEL_BUF_SIZE (32)
#define KDF_CMAC_CONTEXT_BUF_SIZE (32)

/* Input Label parameter */
static uint8_t m_kdf_cmac_label_buf[KDF_CMAC_LABEL_BUF_SIZE];
/* Input Context parameter */
static uint8_t m_kdf_cmac_context_buf[KDF_CMAC_CONTEXT_BUF_SIZE];
/* Output key material */
static uint8_t m_kdf_cmac_ko_buf[KDF_CMAC_KO_BUF_SIZE];
/* Expected output key material */
static uint8_t m_kdf_cmac_expected_ko_buf[KDF_CMAC_KO_BUF_SIZE];

static test_vector_kdf_cmac_t *p_test_vector;

static size_t ko_len;
static size_t label_len;
static size_t context_len;
static size_t expected_ko_len;


void kdf_cmac_clear_buffers(void)
{
	memset(m_kdf_cmac_context_buf, 0x00, sizeof(m_kdf_cmac_context_buf));
	memset(m_kdf_cmac_label_buf, 0x00, sizeof(m_kdf_cmac_label_buf));
	memset(m_kdf_cmac_ko_buf, 0xFF, sizeof(m_kdf_cmac_ko_buf));
	memset(m_kdf_cmac_expected_ko_buf, 0x00, sizeof(m_kdf_cmac_expected_ko_buf));
}

__attribute__((noinline)) void unhexify_kdf_cmac(void)
{
	/* Fetch and unhexify test vectors. */
	label_len = hex2bin(p_test_vector->p_label, strlen(p_test_vector->p_label),
			   m_kdf_cmac_label_buf, strlen(p_test_vector->p_label));
	context_len = hex2bin(p_test_vector->p_context, strlen(p_test_vector->p_context),
			   m_kdf_cmac_context_buf, strlen(p_test_vector->p_context));
	expected_ko_len =
		hex2bin(p_test_vector->p_ko, strlen(p_test_vector->p_ko),
			m_kdf_cmac_expected_ko_buf, strlen(p_test_vector->p_ko));
	ko_len = expected_ko_len;
}

void kdf_cmac_setup(void)
{
	static uint32_t i;

	// initialize_cc3xx();
	kdf_cmac_clear_buffers();
	p_test_vector =
		ITEM_GET(test_vector_kdf_cmac_data, test_vector_kdf_cmac_t, i++);
	unhexify_kdf_cmac();
}

/**@brief Function for the test execution.
 */
void exec_test_case_kdf_cmac(void)
{
	int err_code = -1;

	unsigned int ki_bits_len = p_test_vector->ki_length * BITS_IN_BYTE;

	/* Derive key material using CMAC KDF with counter. */
	start_time_measurement();
	err_code = mbedtls_shadow_key_derive(p_test_vector->ki_slot_id,
					     ki_bits_len,
					     m_kdf_cmac_label_buf,
					     label_len,
					     m_kdf_cmac_context_buf,
					     context_len,
					     m_kdf_cmac_ko_buf,
					     ko_len);
	stop_time_measurement();

	LOG_INF("Error code CMAC KDF: %d, expected: %d", err_code,
		p_test_vector->expected_err_code);
	TEST_VECTOR_ASSERT_EQUAL(p_test_vector->expected_err_code, err_code);

	/* Verify the generated CMAC KDF output key material. */
	TEST_VECTOR_ASSERT_EQUAL(expected_ko_len, ko_len);
	TEST_VECTOR_MEMCMP_ASSERT(m_kdf_cmac_ko_buf, m_kdf_cmac_expected_ko_buf,
				  expected_ko_len,
				  p_test_vector->expected_result,
				  "Incorrect kdf cmac on extract and expand");

	/* Verify that the next two bytes in buffer are not overwritten. */
	TEST_VECTOR_OVERFLOW_ASSERT(m_kdf_cmac_ko_buf, ko_len,
				    "KDF CMAC Ko buffer overflow");

}

ITEM_REGISTER(test_case_kdf_cmac_data, test_case_t test_kdf_cmac) = {
	.p_test_case_name = "KDF CMAC",
	.setup = kdf_cmac_setup,
	.exec = exec_test_case_kdf_cmac,
	.teardown = teardown_pass,
	.vector_type = TV_KDF_CMAC,
	.vectors_start = __start_test_vector_kdf_cmac_data,
	.vectors_stop = __stop_test_vector_kdf_cmac_data,
};
