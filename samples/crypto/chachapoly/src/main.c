/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <stdio.h>
#include <stdlib.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <zephyr/logging/log.h>

#include <cracen_psa.h>

#ifdef CONFIG_BUILD_WITH_TFM
#include <tfm_ns_interface.h>
#endif

#define APP_SUCCESS	    (0)
#define APP_ERROR	    (-1)
#define APP_SUCCESS_MESSAGE "Example finished successfully!"
#define APP_ERROR_MESSAGE   "Example exited with error!"

#define PRINT_HEX(p_label, p_text, len)                                                            \
	({                                                                                         \
		LOG_INF("---- %s (len: %u): ----", p_label, len);                                  \
		LOG_HEXDUMP_INF(p_text, len, "Content:");                                          \
		LOG_INF("---- %s end  ----", p_label);                                             \
	})

LOG_MODULE_REGISTER(chachapoly, LOG_LEVEL_DBG);

/* ====================================================================== */
/*		Global variables/defines for the Chacha20-Poly1305 example		  */

#define NRF_CRYPTO_EXAMPLE_CHACHAPOLY_TEXT_SIZE	      (32)
#define NRF_CRYPTO_EXAMPLE_CHACHAPOLY_ADDITIONAL_SIZE (0)
#define NRF_CRYPTO_EXAMPLE_CHACHAPOLY_NONCE_SIZE      (12)
#define NRF_CRYPTO_EXAMPLE_CHACHAPOLY_TAG_SIZE	      (16)

#define USE_KMU_KEY (1)

/* Chacha20-Poly1305 sample Nonce, DO NOT USE IN PRODUCTION */
static uint8_t m_nonce[12] = {0xac, 0x33, 0xe5, 0x3c, 0xb7, 0x9a,
			      0x2a, 0x07, 0xf5, 0x0e, 0x03, 0x36};

static uint8_t m_key[32] = {0xbb, 0x52, 0xe4, 0x52, 0x6c, 0x12, 0x9d, 0xe7, 0x54, 0x2a, 0x6c,
			    0xaa, 0x05, 0x30, 0xd4, 0x1e, 0x8d, 0xa4, 0x7d, 0x46, 0xf1, 0xad,
			    0xe7, 0xcc, 0xbb, 0xcd, 0x6f, 0xcf, 0xe1, 0xe4, 0x45, 0xe3};

/* Below text is used as plaintext for encryption/decryption */
static uint8_t m_plain_text[32] = {0x70, 0xa2, 0x4f, 0x37, 0x13, 0xb4, 0xb3, 0xfe, 0x51, 0xe0, 0xb1,
				   0xed, 0x87, 0x60, 0xfc, 0x23, 0x6d, 0x22, 0x67, 0xee, 0x19, 0x3d,
				   0x81, 0x2a, 0x93, 0xf8, 0xae, 0x3e, 0xce, 0xf7, 0xfd, 0x83};

static uint8_t m_expected_ciphertext[32] = {0xac, 0xf7, 0x02, 0x4e, 0x47, 0x6e, 0xf0, 0xc4,
					    0xf9, 0x86, 0xb5, 0x46, 0xa0, 0x22, 0xce, 0x67,
					    0xba, 0xa0, 0x2e, 0x31, 0x3f, 0xf4, 0x4a, 0x2b,
					    0x2a, 0xd5, 0xec, 0xf6, 0x97, 0xa8, 0x48, 0xda};

static uint8_t m_expected_tag[32] = {0xa6, 0x56, 0x97, 0x52, 0x09, 0x5d, 0xc1, 0xf8,
				     0x90, 0x19, 0x60, 0xe1, 0x92, 0x29, 0x9a, 0x36};

/* Below text is used as additional data for authentication */
static uint8_t m_additional_data[NRF_CRYPTO_EXAMPLE_CHACHAPOLY_ADDITIONAL_SIZE] = {""};

static uint8_t m_encrypted_text[NRF_CRYPTO_EXAMPLE_CHACHAPOLY_TEXT_SIZE +
				NRF_CRYPTO_EXAMPLE_CHACHAPOLY_TAG_SIZE];

static uint8_t m_decrypted_text[NRF_CRYPTO_EXAMPLE_CHACHAPOLY_TEXT_SIZE];

psa_key_id_t key_id;
/* ====================================================================== */

int crypto_init(void)
{
	psa_status_t status;

	/* Initialize PSA Crypto */
	status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		return APP_ERROR;
	}

	return APP_SUCCESS;
}

int crypto_finish(void)
{
	psa_status_t status;

	/* Destroy the key handle */
	status = psa_destroy_key(key_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_destroy_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	return APP_SUCCESS;
}

int import_key(void)
{
	psa_status_t status;
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	if (USE_KMU_KEY) {
		psa_drv_slot_number_t slot_number = 5;
		LOG_INF("Using KMU key");
		key_id = PSA_KEY_HANDLE_FROM_CRACEN_KMU_SLOT(CRACEN_KMU_KEY_USAGE_SCHEME_RAW, slot_number);

		psa_key_lifetime_t lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
			PSA_KEY_PERSISTENCE_DEFAULT, PSA_KEY_LOCATION_CRACEN_KMU);

		if (cracen_kmu_get_key_slot(key_id, &lifetime, &slot_number) == PSA_SUCCESS) {
			LOG_INF("KMU already written");
			return APP_SUCCESS;
		}

		LOG_INF("KMU not written, writing now");
		psa_set_key_lifetime(&key_attributes, lifetime);
		psa_set_key_id(&key_attributes, key_id);
	} else {
		LOG_INF("Using software key");
		psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	}

	/* Crypto settings for Chacha20-Poly1305 */
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_CHACHA20_POLY1305);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_CHACHA20);
	psa_set_key_bits(&key_attributes, 256);

	/* Generate a random key. The key is not exposed to the application,
	 * we can use it to encrypt/decrypt using the key handle
	 */
	status = psa_import_key(&key_attributes, m_key, sizeof(m_key), &key_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_generate_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	/* After the key handle is acquired the attributes are not needed */
	psa_reset_key_attributes(&key_attributes);

	LOG_INF("ChachaPoly key generated successfully!");

	return APP_SUCCESS;
}

int export_key(void)
{
	uint8_t      key_buf[32];
    size_t       key_length = 0;
    psa_status_t status     = psa_export_key(key_id, key_buf, 32, &key_length);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_export_key failed! (Error: %d)", status);
		return APP_ERROR;
	}
	LOG_INF("ChachaPoly key export successfully!");

	/* Check the validity of the decryption */
	if (memcmp(key_buf, m_key, 32) != 0) {
		LOG_INF("Error: Exported key doesn't match the expected");
		return APP_ERROR;
	}

	return APP_SUCCESS;
}

int encrypt_chachapoly(void)
{
	uint32_t output_len;
	psa_status_t status;

	LOG_INF("Encrypting using Chacha20-Poly1305...");

	/* Perform the authenticated encryption */
	status = psa_aead_encrypt(key_id, PSA_ALG_CHACHA20_POLY1305, m_nonce, sizeof(m_nonce),
				  m_additional_data, 0, m_plain_text, sizeof(m_plain_text),
				  m_encrypted_text, sizeof(m_encrypted_text), &output_len);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_aead_encrypt failed! (Error: %d)", status);
		return APP_ERROR;
	}

	LOG_INF("Encryption successful!");
	PRINT_HEX("Nonce", m_nonce, sizeof(m_nonce));
	PRINT_HEX("Plaintext", m_plain_text, sizeof(m_plain_text));
	PRINT_HEX("Additional data", m_additional_data, sizeof(m_additional_data));
	PRINT_HEX("Encrypted text", m_encrypted_text, sizeof(m_encrypted_text));

	/* Check the validity of the decryption */
	if (memcmp(m_expected_ciphertext, m_encrypted_text, 32) != 0) {
		LOG_INF("Error: Encrypted text doesn't match the expected");
		return APP_ERROR;
	}

	/* Check the validity of the decryption */
	if (memcmp(m_expected_tag, m_encrypted_text + 32, 16) != 0) {
		LOG_INF("Error: TAG doesn't match the expected");
		return APP_ERROR;
	}

	return APP_SUCCESS;
}

int decrypt_chachapoly(void)
{
	uint32_t output_len;
	psa_status_t status;

	LOG_INF("Decrypting using Chacha20-Poly1305 ...");

	/* Decrypt and authenticate the encrypted data */
	status = psa_aead_decrypt(key_id, PSA_ALG_CHACHA20_POLY1305, m_nonce, sizeof(m_nonce),
				  m_additional_data, 0, m_encrypted_text, sizeof(m_encrypted_text),
				  m_decrypted_text, sizeof(m_decrypted_text), &output_len);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_aead_decrypt failed! (Error: %d)", status);
		return APP_ERROR;
	}

	PRINT_HEX("Decrypted text", m_decrypted_text, sizeof(m_decrypted_text));

	/* Check the validity of the decryption */
	if (memcmp(m_decrypted_text, m_plain_text, 32) != 0) {
		LOG_INF("Error: Decrypted text doesn't match the plaintext");
		return APP_ERROR;
	}

	LOG_INF("Decryption and authentication was successful!");

	return APP_SUCCESS;
}

int main(void)
{
	int status;

	LOG_INF("Starting ChachaPoly example...");
	status = crypto_init();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = import_key();
	if (status != APP_SUCCESS) {
		LOG_INF("IMPORT KEY failed! (Error: %d)", status);
		return APP_ERROR;
	}

	status = export_key();
	if (status != APP_SUCCESS) {
		LOG_INF("IMPORT KEY failed! (Error: %d)", status);
		return APP_ERROR;
	}

	status = encrypt_chachapoly();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = decrypt_chachapoly();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = crypto_finish();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	LOG_INF(APP_SUCCESS_MESSAGE);
	return APP_SUCCESS;
}
