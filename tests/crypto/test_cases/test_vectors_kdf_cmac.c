/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stddef.h>

#include "common_test.h"
#include <mbedtls/md.h>


ITEM_REGISTER(test_vector_kdf_cmac_data,
	      test_vector_kdf_cmac_t test_vector_kdf_cmac_1) = {
	.expected_err_code = 0,
	.expected_result = EXPECTED_TO_PASS,
	.p_test_vector_name = TV_NAME("KDF CMAC 128bit-key ko_len=2"),
	.ki_slot_id = 2,
	.ki_length = 16,
	.p_ko = "c3af",
    .p_label = "55534552f24b4559",
    .p_context = "54455354"
};

ITEM_REGISTER(test_vector_kdf_cmac_data,
	      test_vector_kdf_cmac_t test_vector_kdf_cmac_2) = {
	.expected_err_code = 0,
	.expected_result = EXPECTED_TO_PASS,
	.p_test_vector_name = TV_NAME("KDF CMAC 128bit-key ko_len=16"),
	.ki_slot_id = 2,
	.ki_length = 16,
	.p_ko = "ee2dfdc04653b1d55c1d31129f7ccd76",
    .p_label = "55534552f24b4559",
    .p_context = "54455354"
};

ITEM_REGISTER(test_vector_kdf_cmac_data,
	      test_vector_kdf_cmac_t test_vector_kdf_cmac_3) = {
	.expected_err_code = 0,
	.expected_result = EXPECTED_TO_PASS,
	.p_test_vector_name = TV_NAME("KDF CMAC 128bit-key ko_len=32"),
	.ki_slot_id = 2,
	.ki_length = 16,
	.p_ko = "78024b989114247945b21ee9da6cca9170871f0f68c12dbbe6b0c9f19841e5e8",
    .p_label = "55534552f24b4559",
    .p_context = "54455354"
};

ITEM_REGISTER(test_vector_kdf_cmac_data,
	      test_vector_kdf_cmac_t test_vector_kdf_cmac_4) = {
	.expected_err_code = 0,
	.expected_result = EXPECTED_TO_PASS,
	.p_test_vector_name = TV_NAME("KDF CMAC 128bit-key ko_len=1024"),
	.ki_slot_id = 2,
	.ki_length = 16,
	.p_ko = "c4a978a5dc36042816822f0bc3388740c189cf1bf79547f4d9121f1a066766646c81f2a9fbd05e9900c949109f50a56442868af7f8b3ec0da909b3048cea5d88a13c1d5c45cd41d43bd2fed0eade2667b56dca98fbc85a2a67a76ab418eb04838dca3ea2d65bf1e90dee9741bfd7a1767483d6d868b7444a9345f7e1b3742a8a4350676e409646874a5647283f7484eb4e934834fb12be5b76e8f132ce60a3a34a7878c7d121e8b8e89711419d5c0f44b15651dc11093235d22c4d98810b341ca0af3ad12b7297cfe0729d16349e94b297b149227229c34444e13abd55695fa76497dfda5d57783f850ee70b644be6b6d2d3dd6a6b92b31a5e1f673a029b221783a67b4171e417d7ea3fd1c22cc556a4f65ae98a3dfa02f63f19f676eb4cd820e60b0cfdc85982895116a7792463e1865bdcfeaf8a123b239e5728562e0579248f96d2f3f283033a04ad0d320b091bfe77d33137633c0e98f5385853ab9f754a4e161e8786c197161898e5996d1c0559523954b97195e0e41461d3950200524a7eab4140f4bd862cfcabe5ef820aaab38b0285fa30fc10627e4b9666ac56634427fdb5bc3f9ee6b7dc890848b61fed8c91922fe6b2884ef20201f2797f1d1eb387539517845a58f792703076a3deaaa02ece7de1a923952f009b9653ae34c6922e33552e4e26eadf18f4afd0d8615593b2aadf710a00cbec3ad64883865cb776346fa6c052e4e1eea1881013c32a8824f6597d16c5ba919a3f49adedf7afea3f474462211187897b38d46cebcfec3f0bcb73a5e11896cc660a7043923b0df14941299bbe3339f60e69bbf801fc41614ca4bd8c5e2c724959f8cd74264e34b042f0e219c5c7110035208de3cc47a6191025163d0e18e808f86183f71547b2bd16f8c21f0ea1e5d17a41416f99da9c1a7c873d8824cf71b68417a7dfec362de03cb81d753c3257e77db8d631e938878eb1e6991f9fd51d2a0091b5b6d6b72ff4f6e645a6c67b735f869836b956b73a1cfea3df8802e0205a849c4edb14488a5b986cd2ce7bcb715f79d73b433331c4a50ce7d94e6a612c8bc3e7e78216c43f21485ea4809cc386c36108d5e2e213c32072b9e3243c1abe84e6d13395cc4ab94b176b3fc7c26a78c27368b70f57b6c028553e8e9f9a34984cfdb66fbd645503f6e3f1072a58621723e134f40e6127db1394cf3afd646adb950a461a4614e41bd50ae6b8c26723a99da59032b748299d2190d413845a2f1c01a7a2503c9ad87f0f1c2b7d9be435b731b0fe846e5e3a7fc9fe1378162dfc6447f25566f42495a7f2f2df80214b16db51dc6ecbc8373d1820d0b9bc8629a579a52a51917fab1597958ca1ced823c18ca06338c03933b7d6064c0bc5870864edbf501c6551c35875ada57b38b0b4066874b95dd9e63aed7ec3b1e13122d953e00b5ff70606265ba76d80",
    .p_label = "55534552f24b4559",
    .p_context = "54455354"
};

ITEM_REGISTER(test_vector_kdf_cmac_data,
	      test_vector_kdf_cmac_t test_vector_kdf_cmac_5) = {
	.expected_err_code = 0,
	.expected_result = EXPECTED_TO_PASS,
	.p_test_vector_name = TV_NAME("KDF CMAC 256bit-key ko_len=2"),
	.ki_slot_id = 3,
	.ki_length = 32,
	.p_ko = "07eb",
    .p_label = "55534552f24b4559",
    .p_context = "54455354"
};

ITEM_REGISTER(test_vector_kdf_cmac_data,
	      test_vector_kdf_cmac_t test_vector_kdf_cmac_6) = {
	.expected_err_code = 0,
	.expected_result = EXPECTED_TO_PASS,
	.p_test_vector_name = TV_NAME("KDF CMAC Valid 256bit-key ko_len=16"),
	.ki_slot_id = 3,
	.ki_length = 32,
	.p_ko = "2b05e1f8f05878ac41b0b55db0429e5c",
    .p_label = "55534552f24b4559",
    .p_context = "54455354"
};

ITEM_REGISTER(test_vector_kdf_cmac_data,
	      test_vector_kdf_cmac_t test_vector_kdf_cmac_7) = {
	.expected_err_code = 0,
	.expected_result = EXPECTED_TO_PASS,
	.p_test_vector_name = TV_NAME("KDF CMAC Valid 256bit-key ko_len=32"),
	.ki_slot_id = 3,
	.ki_length = 32,
	.p_ko = "f4334c8e841f9a65478a37b631d22b9ef9c26cb9c2e4902394bf099722bdec53",
    .p_label = "55534552f24b4559",
    .p_context = "54455354"
};

ITEM_REGISTER(test_vector_kdf_cmac_data,
	      test_vector_kdf_cmac_t test_vector_kdf_cmac_8) = {
	.expected_err_code = 0,
	.expected_result = EXPECTED_TO_PASS,
	.p_test_vector_name = TV_NAME("KDF CMAC Valid 256bit-key ko_len=1024"),
	.ki_slot_id = 3,
	.ki_length = 32,
	.p_ko = "76aaeafc9d41ce2f924589c0f3277d2597044352e6188702f2959e28461fa5927087d8bdc49c11583115f9360532ebaa7cb4038ef6aaaaa7838e83db1a31923a0b17bf8fdff0e14b2086b0609b2549025c0732bc0368088164bac0760a10d0bb1001cfeaa9ff836ea82235a37947de816cba28e7458475fd8fc2fdf20d69c876d29ccd5063bdef1826a8558a4239b367aa0ebe1a242958ede45a8501643c3a21270862c3b0de36d0302b086b7065069b68dbadfd4e8ba7ea767a0b419a90ada3544225b6df61bb0904c5fbdeba12d40adf8c4221eec0d902cd363fb5f5aeb23c70c7c4a564be2a475cc898e9704bcbe91bc1879bd0757538ff71d7b6c8b471d12128a64c333b239a6f085d267a7d11b5fa5bf3e7a7ee235d8a3f9770ed4d226b68edc704a6b657e39d29458734c2bba66859197051c4f130af86c40f288df702d670dd06c804c4e32fa0a8a555f004b512bf7195e6eaf3a0e29f9b6c44fcdee41a061a6734a3a6c9b64612200c0f40e9d69fcaf05bbbbba54abd8efc98009b6b69a9bbb88033794b92d710bab3f3cbc9e65d507fbd2d792d827c6437a7da5b4dae92d61681840e9a166dd0727eb50fed57cfc8407f95f07b1a0ead41891e288f74183bbe69e3d8a2ea24c9816ce974a305159ba45f6162c863550b3fb6f8f12a4063e54facea65cc7327a686e7c82eaf522f58871783e30e6c871aff6ef8e3b8134871b4af27b88d653a07b74247a31d0864f50f90151359013bc7b2de54a6ebadad94c6cf39eb33c0fc04ac808e6af671272969f43d4a8a1dd83cfdba989b9f5ad08470348910586f3529f0c4807219cdc536b35e2582076d0f9d869e98f30703122eb039094aa602e46fa3c82aa09d11b32a747ae8d476467aa2ada8224b20fc1789ae7ff0412504b1f4c569c788d7935e7ec20df2ee45e0756a521bb75e9fbb4a2f40110b0c6a287b2de594ef9604e26f388aaab4e81f4a6c29c35232bebecfdbbcec3cf763ff02d0fef97f36d142c1673fb2b3d3619ca894db3bc4a40815d2c4bc62766c8c5bcd954c555151e746ee302b1a44e4073345abf1aa595f9da2d92b2633210ce334408cb3f90a5d66ec4c5b101c940d188624590ecb67332b3f58088f42ffdf9fbd8dc12382ec8d4ec9a6479d501196f6dc9a5330c43b7416808fd4bcdfeb08dbd735726ef5f6808d957b17f894871271276cf00ba84e89a4ba41946cdcc4ce9d6b7b3e936bbb4b6ba77772db21ab74803e7c86edd949a38870648041b8f001fc9d1dd8d5a553408581d725e942dc90b5ff63e0f8182c53d4ee611b60b3021d6508ceafac32f8120e19f70fc35f68e11725581652a1f24d5fbd32207f087ad178d70b56a4841e1dca5b384e8c416f39a32cece412445386493c18f7f61af74a0cbba5321ce834ca152a5aef01538506bddc9eb3e34acbd866c3",
    .p_label = "55534552f24b4559",
    .p_context = "54455354"
};
