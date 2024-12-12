# Details

Date : 2024-12-10 16:29:29

Directory /home/aping/code/mpc/mpc-tss

Total : 240 files,  22932 codes, 2019 comments, 3998 blanks, all 28949 lines

[Summary](results.md) / Details / [Diff Summary](diff.md) / [Diff Details](diff-details.md)

## Files
| filename | language | code | comment | blank | total |
| :--- | :--- | ---: | ---: | ---: | ---: |
| [README.md](/README.md) | Markdown | 17 | 0 | 11 | 28 |
| [common/hash.go](/common/hash.go) | Go | 121 | 28 | 8 | 157 |
| [common/hash_utils.go](/common/hash_utils.go) | Go | 8 | 7 | 4 | 19 |
| [common/hash_utils_test.go](/common/hash_utils_test.go) | Go | 54 | 5 | 5 | 64 |
| [common/int.go](/common/int.go) | Go | 48 | 6 | 14 | 68 |
| [common/logger.go](/common/logger.go) | Go | 5 | 5 | 4 | 14 |
| [common/pool/pool.go](/common/pool/pool.go) | Go | 143 | 62 | 26 | 231 |
| [common/random.go](/common/random.go) | Go | 97 | 18 | 16 | 131 |
| [common/random_test.go](/common/random_test.go) | Go | 33 | 6 | 10 | 49 |
| [common/safe_prime.go](/common/safe_prime.go) | Go | 178 | 134 | 43 | 355 |
| [common/safe_prime_test.go](/common/safe_prime_test.go) | Go | 43 | 5 | 9 | 57 |
| [common/sample/prime.go](/common/sample/prime.go) | Go | 118 | 43 | 20 | 181 |
| [common/sample/sample_test.go](/common/sample/sample_test.go) | Go | 30 | 3 | 10 | 43 |
| [common/signature.pb.go](/common/signature.pb.go) | Go | 151 | 17 | 23 | 191 |
| [common/slice.go](/common/slice.go) | Go | 47 | 10 | 8 | 65 |
| [crypto/affproof/aff_msg.pb.go](/crypto/affproof/aff_msg.pb.go) | Go | 388 | 9 | 53 | 450 |
| [crypto/affproof/aff_msg.proto](/crypto/affproof/aff_msg.proto) | Protocol Buffers | 36 | 0 | 5 | 41 |
| [crypto/affproof/affg_proof.go](/crypto/affproof/affg_proof.go) | Go | 289 | 21 | 15 | 325 |
| [crypto/affproof/affg_proof_test.go](/crypto/affproof/affg_proof_test.go) | Go | 55 | 2 | 8 | 65 |
| [crypto/affproof/affp_proof.go](/crypto/affproof/affp_proof.go) | Go | 265 | 20 | 10 | 295 |
| [crypto/affproof/affp_proof_test.go](/crypto/affproof/affp_proof_test.go) | Go | 33 | 2 | 6 | 41 |
| [crypto/alice/README.md](/crypto/alice/README.md) | Markdown | 2 | 0 | 2 | 4 |
| [crypto/alice/mta/mta.go](/crypto/alice/mta/mta.go) | Go | 103 | 15 | 9 | 127 |
| [crypto/alice/paillier/message.go](/crypto/alice/paillier/message.go) | Go | 30 | 15 | 7 | 52 |
| [crypto/alice/paillier/message.pb.go](/crypto/alice/paillier/message.pb.go) | Go | 139 | 21 | 20 | 180 |
| [crypto/alice/paillier/paillier.go](/crypto/alice/paillier/paillier.go) | Go | 310 | 43 | 50 | 403 |
| [crypto/alice/paillier/ringpedersen.go](/crypto/alice/paillier/ringpedersen.go) | Go | 80 | 15 | 16 | 111 |
| [crypto/alice/utils/message.pb.go](/crypto/alice/utils/message.pb.go) | Go | 126 | 21 | 19 | 166 |
| [crypto/alice/utils/prime.go](/crypto/alice/utils/prime.go) | Go | 204 | 37 | 14 | 255 |
| [crypto/alice/utils/utils.go](/crypto/alice/utils/utils.go) | Go | 320 | 55 | 40 | 415 |
| [crypto/alice/zkproof/integerfactorization.go](/crypto/alice/zkproof/integerfactorization.go) | Go | 111 | 50 | 27 | 188 |
| [crypto/alice/zkproof/message.pb.go](/crypto/alice/zkproof/message.pb.go) | Go | 144 | 21 | 22 | 187 |
| [crypto/alice/zkproof/paillier/message.pb.go](/crypto/alice/zkproof/paillier/message.pb.go) | Go | 354 | 25 | 51 | 430 |
| [crypto/alice/zkproof/paillier/pederssen_open_parameter.go](/crypto/alice/zkproof/paillier/pederssen_open_parameter.go) | Go | 25 | 13 | 8 | 46 |
| [crypto/alice/zkproof/paillier/utils.go](/crypto/alice/zkproof/paillier/utils.go) | Go | 31 | 4 | 8 | 43 |
| [crypto/ckd/child_key_derivation.go](/crypto/ckd/child_key_derivation.go) | Go | 220 | 26 | 41 | 287 |
| [crypto/ckd/child_key_derivation_test.go](/crypto/ckd/child_key_derivation_test.go) | Go | 223 | 9 | 26 | 258 |
| [crypto/commitments/commitment.go](/crypto/commitments/commitment.go) | Go | 51 | 10 | 14 | 75 |
| [crypto/commitments/commitment_builder.go](/crypto/commitments/commitment_builder.go) | Go | 77 | 5 | 10 | 92 |
| [crypto/commitments/commitment_builder_test.go](/crypto/commitments/commitment_builder_test.go) | Go | 141 | 8 | 6 | 155 |
| [crypto/commitments/commitment_test.go](/crypto/commitments/commitment_test.go) | Go | 23 | 5 | 12 | 40 |
| [crypto/config.go](/crypto/config.go) | Go | 33 | 1 | 7 | 41 |
| [crypto/ecpoint.go](/crypto/ecpoint.go) | Go | 240 | 16 | 43 | 299 |
| [crypto/ecpoint_test.go](/crypto/ecpoint_test.go) | Go | 148 | 5 | 18 | 171 |
| [crypto/encproof/enc_msg.pb.go](/crypto/encproof/enc_msg.pb.go) | Go | 166 | 8 | 24 | 198 |
| [crypto/encproof/enc_msg.proto](/crypto/encproof/enc_msg.proto) | Protocol Buffers | 12 | 0 | 4 | 16 |
| [crypto/encproof/proof.go](/crypto/encproof/proof.go) | Go | 148 | 18 | 15 | 181 |
| [crypto/encproof/proof_test.go](/crypto/encproof/proof_test.go) | Go | 42 | 2 | 8 | 52 |
| [crypto/facproof/fac_msg.pb.go](/crypto/facproof/fac_msg.pb.go) | Go | 207 | 8 | 29 | 244 |
| [crypto/facproof/fac_msg.proto](/crypto/facproof/fac_msg.proto) | Protocol Buffers | 17 | 0 | 4 | 21 |
| [crypto/facproof/proof.go](/crypto/facproof/proof.go) | Go | 153 | 16 | 13 | 182 |
| [crypto/facproof/proof_test.go](/crypto/facproof/proof_test.go) | Go | 37 | 2 | 8 | 47 |
| [crypto/logproof/log_msg.pb.go](/crypto/logproof/log_msg.pb.go) | Go | 182 | 8 | 26 | 216 |
| [crypto/logproof/log_msg.proto](/crypto/logproof/log_msg.proto) | Protocol Buffers | 14 | 0 | 4 | 18 |
| [crypto/logproof/proof.go](/crypto/logproof/proof.go) | Go | 177 | 21 | 19 | 217 |
| [crypto/logproof/proof_test.go](/crypto/logproof/proof_test.go) | Go | 113 | 2 | 21 | 136 |
| [crypto/modproof/mod_msg.pb.go](/crypto/modproof/mod_msg.pb.go) | Go | 158 | 8 | 23 | 189 |
| [crypto/modproof/mod_msg.proto](/crypto/modproof/mod_msg.proto) | Protocol Buffers | 11 | 0 | 4 | 15 |
| [crypto/modproof/proof.go](/crypto/modproof/proof.go) | Go | 228 | 30 | 34 | 292 |
| [crypto/modproof/proof_test.go](/crypto/modproof/proof_test.go) | Go | 21 | 15 | 7 | 43 |
| [crypto/paillier/paillier.go](/crypto/paillier/paillier.go) | Go | 249 | 39 | 37 | 325 |
| [crypto/paillier/paillier_test.go](/crypto/paillier/paillier_test.go) | Go | 120 | 8 | 30 | 158 |
| [crypto/prmproof/prm_msg.pb.go](/crypto/prmproof/prm_msg.pb.go) | Go | 158 | 8 | 23 | 189 |
| [crypto/prmproof/prm_msg.proto](/crypto/prmproof/prm_msg.proto) | Protocol Buffers | 11 | 0 | 4 | 15 |
| [crypto/prmproof/proof.go](/crypto/prmproof/proof.go) | Go | 109 | 24 | 19 | 152 |
| [crypto/prmproof/proof_test.go](/crypto/prmproof/proof_test.go) | Go | 25 | 0 | 8 | 33 |
| [crypto/schnorr/schnorr_proof.go](/crypto/schnorr/schnorr_proof.go) | Go | 126 | 8 | 24 | 158 |
| [crypto/schnorr/schnorr_proof_test.go](/crypto/schnorr/schnorr_proof_test.go) | Go | 78 | 5 | 23 | 106 |
| [crypto/vss/feldman_vss.go](/crypto/vss/feldman_vss.go) | Go | 133 | 19 | 25 | 177 |
| [crypto/vss/feldman_vss_test.go](/crypto/vss/feldman_vss_test.go) | Go | 83 | 7 | 28 | 118 |
| [go.mod](/go.mod) | Go Module File | 42 | 0 | 7 | 49 |
| [go.sum](/go.sum) | Go Checksum File | 223 | 0 | 1 | 224 |
| [protob/message.proto](/protob/message.proto) | Protocol Buffers | 35 | 0 | 8 | 43 |
| [protob/signature.proto](/protob/signature.proto) | Protocol Buffers | 20 | 0 | 7 | 27 |
| [protocols/cggmp/auxiliary/README.md](/protocols/cggmp/auxiliary/README.md) | Markdown | 2 | 0 | 2 | 4 |
| [protocols/cggmp/auxiliary/auxiliary.pb.go](/protocols/cggmp/auxiliary/auxiliary.pb.go) | Go | 295 | 13 | 42 | 350 |
| [protocols/cggmp/auxiliary/auxiliary.proto](/protocols/cggmp/auxiliary/auxiliary.proto) | Protocol Buffers | 30 | 0 | 5 | 35 |
| [protocols/cggmp/auxiliary/local_party.go](/protocols/cggmp/auxiliary/local_party.go) | Go | 129 | 12 | 28 | 169 |
| [protocols/cggmp/auxiliary/local_party_test.go](/protocols/cggmp/auxiliary/local_party_test.go) | Go | 156 | 11 | 34 | 201 |
| [protocols/cggmp/auxiliary/messages.go](/protocols/cggmp/auxiliary/messages.go) | Go | 133 | 6 | 21 | 160 |
| [protocols/cggmp/auxiliary/prepare.go](/protocols/cggmp/auxiliary/prepare.go) | Go | 74 | 19 | 17 | 110 |
| [protocols/cggmp/auxiliary/round_1.go](/protocols/cggmp/auxiliary/round_1.go) | Go | 115 | 5 | 19 | 139 |
| [protocols/cggmp/auxiliary/round_2.go](/protocols/cggmp/auxiliary/round_2.go) | Go | 66 | 0 | 13 | 79 |
| [protocols/cggmp/auxiliary/round_3.go](/protocols/cggmp/auxiliary/round_3.go) | Go | 140 | 5 | 24 | 169 |
| [protocols/cggmp/auxiliary/round_final.go](/protocols/cggmp/auxiliary/round_final.go) | Go | 55 | 4 | 15 | 74 |
| [protocols/cggmp/auxiliary/rounds.go](/protocols/cggmp/auxiliary/rounds.go) | Go | 77 | 5 | 13 | 95 |
| [protocols/cggmp/auxiliary/save_data.go](/protocols/cggmp/auxiliary/save_data.go) | Go | 45 | 3 | 10 | 58 |
| [protocols/cggmp/auxiliary/test_utils.go](/protocols/cggmp/auxiliary/test_utils.go) | Go | 59 | 4 | 7 | 70 |
| [protocols/cggmp/ecdsa/presign/local_party.go](/protocols/cggmp/ecdsa/presign/local_party.go) | Go | 140 | 11 | 31 | 182 |
| [protocols/cggmp/ecdsa/presign/local_party_test.go](/protocols/cggmp/ecdsa/presign/local_party_test.go) | Go | 175 | 13 | 38 | 226 |
| [protocols/cggmp/ecdsa/presign/round_1.go](/protocols/cggmp/ecdsa/presign/round_1.go) | Go | 126 | 6 | 20 | 152 |
| [protocols/cggmp/ecdsa/presign/round_2.go](/protocols/cggmp/ecdsa/presign/round_2.go) | Go | 146 | 7 | 23 | 176 |
| [protocols/cggmp/ecdsa/presign/round_3.go](/protocols/cggmp/ecdsa/presign/round_3.go) | Go | 169 | 9 | 36 | 214 |
| [protocols/cggmp/ecdsa/presign/round_final.go](/protocols/cggmp/ecdsa/presign/round_final.go) | Go | 69 | 2 | 19 | 90 |
| [protocols/cggmp/ecdsa/presign/rounds.go](/protocols/cggmp/ecdsa/presign/rounds.go) | Go | 99 | 6 | 15 | 120 |
| [protocols/cggmp/ecdsa/presign/save_data.go](/protocols/cggmp/ecdsa/presign/save_data.go) | Go | 59 | 4 | 9 | 72 |
| [protocols/cggmp/ecdsa/presign/test_utils.go](/protocols/cggmp/ecdsa/presign/test_utils.go) | Go | 58 | 0 | 9 | 67 |
| [protocols/cggmp/ecdsa/sign/local_party.go](/protocols/cggmp/ecdsa/sign/local_party.go) | Go | 157 | 13 | 31 | 201 |
| [protocols/cggmp/ecdsa/sign/local_party_test.go](/protocols/cggmp/ecdsa/sign/local_party_test.go) | Go | 198 | 19 | 46 | 263 |
| [protocols/cggmp/ecdsa/sign/messages.go](/protocols/cggmp/ecdsa/sign/messages.go) | Go | 237 | 7 | 34 | 278 |
| [protocols/cggmp/ecdsa/sign/round_1.go](/protocols/cggmp/ecdsa/sign/round_1.go) | Go | 122 | 6 | 19 | 147 |
| [protocols/cggmp/ecdsa/sign/round_2.go](/protocols/cggmp/ecdsa/sign/round_2.go) | Go | 135 | 16 | 23 | 174 |
| [protocols/cggmp/ecdsa/sign/round_3.go](/protocols/cggmp/ecdsa/sign/round_3.go) | Go | 158 | 18 | 36 | 212 |
| [protocols/cggmp/ecdsa/sign/round_4.go](/protocols/cggmp/ecdsa/sign/round_4.go) | Go | 87 | 1 | 21 | 109 |
| [protocols/cggmp/ecdsa/sign/round_final.go](/protocols/cggmp/ecdsa/sign/round_final.go) | Go | 83 | 8 | 20 | 111 |
| [protocols/cggmp/ecdsa/sign/rounds.go](/protocols/cggmp/ecdsa/sign/rounds.go) | Go | 99 | 6 | 15 | 120 |
| [protocols/cggmp/ecdsa/sign/sign.pb.go](/protocols/cggmp/ecdsa/sign/sign.pb.go) | Go | 430 | 17 | 61 | 508 |
| [protocols/cggmp/ecdsa/sign/sign.proto](/protocols/cggmp/ecdsa/sign/sign.proto) | Protocol Buffers | 44 | 0 | 6 | 50 |
| [protocols/cggmp/ecdsa/signing/local_party.go](/protocols/cggmp/ecdsa/signing/local_party.go) | Go | 128 | 10 | 24 | 162 |
| [protocols/cggmp/ecdsa/signing/local_party_test.go](/protocols/cggmp/ecdsa/signing/local_party_test.go) | Go | 186 | 16 | 41 | 243 |
| [protocols/cggmp/ecdsa/signing/prepare.go](/protocols/cggmp/ecdsa/signing/prepare.go) | Go | 29 | 0 | 6 | 35 |
| [protocols/cggmp/ecdsa/signing/round_1.go](/protocols/cggmp/ecdsa/signing/round_1.go) | Go | 74 | 2 | 15 | 91 |
| [protocols/cggmp/ecdsa/signing/round_final.go](/protocols/cggmp/ecdsa/signing/round_final.go) | Go | 84 | 8 | 20 | 112 |
| [protocols/cggmp/ecdsa/signing/rounds.go](/protocols/cggmp/ecdsa/signing/rounds.go) | Go | 87 | 6 | 15 | 108 |
| [protocols/cggmp/eddsa/presign/local_party.go](/protocols/cggmp/eddsa/presign/local_party.go) | Go | 123 | 9 | 27 | 159 |
| [protocols/cggmp/eddsa/presign/local_party_test.go](/protocols/cggmp/eddsa/presign/local_party_test.go) | Go | 176 | 11 | 37 | 224 |
| [protocols/cggmp/eddsa/presign/round_1.go](/protocols/cggmp/eddsa/presign/round_1.go) | Go | 122 | 6 | 22 | 150 |
| [protocols/cggmp/eddsa/presign/round_2.go](/protocols/cggmp/eddsa/presign/round_2.go) | Go | 97 | 4 | 20 | 121 |
| [protocols/cggmp/eddsa/presign/round_final.go](/protocols/cggmp/eddsa/presign/round_final.go) | Go | 71 | 4 | 21 | 96 |
| [protocols/cggmp/eddsa/presign/rounds.go](/protocols/cggmp/eddsa/presign/rounds.go) | Go | 91 | 6 | 15 | 112 |
| [protocols/cggmp/eddsa/presign/save_data.go](/protocols/cggmp/eddsa/presign/save_data.go) | Go | 57 | 4 | 9 | 70 |
| [protocols/cggmp/eddsa/presign/test_utils.go](/protocols/cggmp/eddsa/presign/test_utils.go) | Go | 58 | 0 | 9 | 67 |
| [protocols/cggmp/eddsa/presign/utils.go](/protocols/cggmp/eddsa/presign/utils.go) | Go | 78 | 7 | 23 | 108 |
| [protocols/cggmp/eddsa/sign/local_party.go](/protocols/cggmp/eddsa/sign/local_party.go) | Go | 139 | 12 | 30 | 181 |
| [protocols/cggmp/eddsa/sign/local_party_test.go](/protocols/cggmp/eddsa/sign/local_party_test.go) | Go | 204 | 16 | 45 | 265 |
| [protocols/cggmp/eddsa/sign/messages.go](/protocols/cggmp/eddsa/sign/messages.go) | Go | 127 | 6 | 22 | 155 |
| [protocols/cggmp/eddsa/sign/round_1.go](/protocols/cggmp/eddsa/sign/round_1.go) | Go | 118 | 6 | 21 | 145 |
| [protocols/cggmp/eddsa/sign/round_2.go](/protocols/cggmp/eddsa/sign/round_2.go) | Go | 96 | 4 | 20 | 120 |
| [protocols/cggmp/eddsa/sign/round_3.go](/protocols/cggmp/eddsa/sign/round_3.go) | Go | 106 | 6 | 26 | 138 |
| [protocols/cggmp/eddsa/sign/round_final.go](/protocols/cggmp/eddsa/sign/round_final.go) | Go | 64 | 3 | 17 | 84 |
| [protocols/cggmp/eddsa/sign/rounds.go](/protocols/cggmp/eddsa/sign/rounds.go) | Go | 95 | 6 | 15 | 116 |
| [protocols/cggmp/eddsa/sign/sign.pb.go](/protocols/cggmp/eddsa/sign/sign.pb.go) | Go | 296 | 15 | 44 | 355 |
| [protocols/cggmp/eddsa/sign/sign.proto](/protocols/cggmp/eddsa/sign/sign.proto) | Protocol Buffers | 29 | 0 | 5 | 34 |
| [protocols/cggmp/eddsa/sign/utils.go](/protocols/cggmp/eddsa/sign/utils.go) | Go | 91 | 7 | 26 | 124 |
| [protocols/cggmp/eddsa/signing/local_party.go](/protocols/cggmp/eddsa/signing/local_party.go) | Go | 140 | 9 | 26 | 175 |
| [protocols/cggmp/eddsa/signing/local_party_test.go](/protocols/cggmp/eddsa/signing/local_party_test.go) | Go | 202 | 15 | 46 | 263 |
| [protocols/cggmp/eddsa/signing/round_1.go](/protocols/cggmp/eddsa/signing/round_1.go) | Go | 114 | 6 | 24 | 144 |
| [protocols/cggmp/eddsa/signing/round_final.go](/protocols/cggmp/eddsa/signing/round_final.go) | Go | 65 | 3 | 18 | 86 |
| [protocols/cggmp/eddsa/signing/rounds.go](/protocols/cggmp/eddsa/signing/rounds.go) | Go | 87 | 6 | 15 | 108 |
| [protocols/cggmp/eddsa/signing/utils.go](/protocols/cggmp/eddsa/signing/utils.go) | Go | 58 | 7 | 18 | 83 |
| [protocols/cggmp/keygen/non_threshold/keygen.pb.go](/protocols/cggmp/keygen/non_threshold/keygen.pb.go) | Go | 297 | 13 | 42 | 352 |
| [protocols/cggmp/keygen/non_threshold/keygen.proto](/protocols/cggmp/keygen/non_threshold/keygen.proto) | Protocol Buffers | 30 | 0 | 5 | 35 |
| [protocols/cggmp/keygen/non_threshold/local_party.go](/protocols/cggmp/keygen/non_threshold/local_party.go) | Go | 119 | 15 | 30 | 164 |
| [protocols/cggmp/keygen/non_threshold/local_party_test.go](/protocols/cggmp/keygen/non_threshold/local_party_test.go) | Go | 239 | 17 | 44 | 300 |
| [protocols/cggmp/keygen/non_threshold/messages.go](/protocols/cggmp/keygen/non_threshold/messages.go) | Go | 112 | 6 | 18 | 136 |
| [protocols/cggmp/keygen/non_threshold/round_1.go](/protocols/cggmp/keygen/non_threshold/round_1.go) | Go | 86 | 3 | 17 | 106 |
| [protocols/cggmp/keygen/non_threshold/round_2.go](/protocols/cggmp/keygen/non_threshold/round_2.go) | Go | 59 | 0 | 11 | 70 |
| [protocols/cggmp/keygen/non_threshold/round_3.go](/protocols/cggmp/keygen/non_threshold/round_3.go) | Go | 105 | 4 | 20 | 129 |
| [protocols/cggmp/keygen/non_threshold/round_final.go](/protocols/cggmp/keygen/non_threshold/round_final.go) | Go | 71 | 3 | 18 | 92 |
| [protocols/cggmp/keygen/non_threshold/rounds.go](/protocols/cggmp/keygen/non_threshold/rounds.go) | Go | 78 | 5 | 13 | 96 |
| [protocols/cggmp/keygen/non_threshold/test_utils.go](/protocols/cggmp/keygen/non_threshold/test_utils.go) | Go | 103 | 2 | 9 | 114 |
| [protocols/cggmp/keygen/save_data.go](/protocols/cggmp/keygen/save_data.go) | Go | 67 | 6 | 12 | 85 |
| [protocols/cggmp/keygen/threshold/local_party.go](/protocols/cggmp/keygen/threshold/local_party.go) | Go | 133 | 13 | 30 | 176 |
| [protocols/cggmp/keygen/threshold/local_party_test.go](/protocols/cggmp/keygen/threshold/local_party_test.go) | Go | 274 | 24 | 52 | 350 |
| [protocols/cggmp/keygen/threshold/messages.go](/protocols/cggmp/keygen/threshold/messages.go) | Go | 121 | 7 | 22 | 150 |
| [protocols/cggmp/keygen/threshold/round_1.go](/protocols/cggmp/keygen/threshold/round_1.go) | Go | 109 | 9 | 20 | 138 |
| [protocols/cggmp/keygen/threshold/round_2.go](/protocols/cggmp/keygen/threshold/round_2.go) | Go | 80 | 3 | 12 | 95 |
| [protocols/cggmp/keygen/threshold/round_3.go](/protocols/cggmp/keygen/threshold/round_3.go) | Go | 176 | 9 | 27 | 212 |
| [protocols/cggmp/keygen/threshold/round_final.go](/protocols/cggmp/keygen/threshold/round_final.go) | Go | 54 | 3 | 15 | 72 |
| [protocols/cggmp/keygen/threshold/rounds.go](/protocols/cggmp/keygen/threshold/rounds.go) | Go | 78 | 5 | 13 | 96 |
| [protocols/cggmp/keygen/threshold/test_utils.go](/protocols/cggmp/keygen/threshold/test_utils.go) | Go | 107 | 2 | 9 | 118 |
| [protocols/cggmp/keygen/threshold/tkeygen.pb.go](/protocols/cggmp/keygen/threshold/tkeygen.pb.go) | Go | 332 | 15 | 48 | 395 |
| [protocols/cggmp/keygen/threshold/tkeygen.proto](/protocols/cggmp/keygen/threshold/tkeygen.proto) | Protocol Buffers | 34 | 0 | 6 | 40 |
| [protocols/cggmp/test/_auxiliary_fixtures/ecdsa_auxiliary_data_0.json](/protocols/cggmp/test/_auxiliary_fixtures/ecdsa_auxiliary_data_0.json) | JSON | 1 | 0 | 0 | 1 |
| [protocols/cggmp/test/_auxiliary_fixtures/ecdsa_auxiliary_data_1.json](/protocols/cggmp/test/_auxiliary_fixtures/ecdsa_auxiliary_data_1.json) | JSON | 1 | 0 | 0 | 1 |
| [protocols/cggmp/test/_auxiliary_fixtures/ecdsa_auxiliary_data_2.json](/protocols/cggmp/test/_auxiliary_fixtures/ecdsa_auxiliary_data_2.json) | JSON | 1 | 0 | 0 | 1 |
| [protocols/cggmp/test/_auxiliary_fixtures/ecdsa_auxiliary_data_3.json](/protocols/cggmp/test/_auxiliary_fixtures/ecdsa_auxiliary_data_3.json) | JSON | 1 | 0 | 0 | 1 |
| [protocols/cggmp/test/_auxiliary_fixtures/ecdsa_auxiliary_data_4.json](/protocols/cggmp/test/_auxiliary_fixtures/ecdsa_auxiliary_data_4.json) | JSON | 1 | 0 | 0 | 1 |
| [protocols/cggmp/test/_auxiliary_fixtures/eddsa_auxiliary_data_0.json](/protocols/cggmp/test/_auxiliary_fixtures/eddsa_auxiliary_data_0.json) | JSON | 31 | 0 | 1 | 32 |
| [protocols/cggmp/test/_auxiliary_fixtures/eddsa_auxiliary_data_1.json](/protocols/cggmp/test/_auxiliary_fixtures/eddsa_auxiliary_data_1.json) | JSON | 31 | 0 | 1 | 32 |
| [protocols/cggmp/test/_auxiliary_fixtures/eddsa_auxiliary_data_2.json](/protocols/cggmp/test/_auxiliary_fixtures/eddsa_auxiliary_data_2.json) | JSON | 31 | 0 | 1 | 32 |
| [protocols/cggmp/test/_keygen_fixtures/non_threshold/ecdsa_keygen_data_0.json](/protocols/cggmp/test/_keygen_fixtures/non_threshold/ecdsa_keygen_data_0.json) | JSON | 20 | 0 | 1 | 21 |
| [protocols/cggmp/test/_keygen_fixtures/non_threshold/ecdsa_keygen_data_1.json](/protocols/cggmp/test/_keygen_fixtures/non_threshold/ecdsa_keygen_data_1.json) | JSON | 20 | 0 | 1 | 21 |
| [protocols/cggmp/test/_keygen_fixtures/non_threshold/ecdsa_keygen_data_2.json](/protocols/cggmp/test/_keygen_fixtures/non_threshold/ecdsa_keygen_data_2.json) | JSON | 20 | 0 | 1 | 21 |
| [protocols/cggmp/test/_keygen_fixtures/non_threshold/eddsa_keygen_data_0.json](/protocols/cggmp/test/_keygen_fixtures/non_threshold/eddsa_keygen_data_0.json) | JSON | 20 | 0 | 1 | 21 |
| [protocols/cggmp/test/_keygen_fixtures/non_threshold/eddsa_keygen_data_1.json](/protocols/cggmp/test/_keygen_fixtures/non_threshold/eddsa_keygen_data_1.json) | JSON | 20 | 0 | 1 | 21 |
| [protocols/cggmp/test/_keygen_fixtures/non_threshold/eddsa_keygen_data_2.json](/protocols/cggmp/test/_keygen_fixtures/non_threshold/eddsa_keygen_data_2.json) | JSON | 20 | 0 | 1 | 21 |
| [protocols/cggmp/test/_keygen_fixtures/threshold/ecdsa_keygen_data_0.json](/protocols/cggmp/test/_keygen_fixtures/threshold/ecdsa_keygen_data_0.json) | JSON | 1 | 0 | 0 | 1 |
| [protocols/cggmp/test/_keygen_fixtures/threshold/ecdsa_keygen_data_1.json](/protocols/cggmp/test/_keygen_fixtures/threshold/ecdsa_keygen_data_1.json) | JSON | 1 | 0 | 0 | 1 |
| [protocols/cggmp/test/_keygen_fixtures/threshold/ecdsa_keygen_data_2.json](/protocols/cggmp/test/_keygen_fixtures/threshold/ecdsa_keygen_data_2.json) | JSON | 1 | 0 | 0 | 1 |
| [protocols/cggmp/test/_keygen_fixtures/threshold/ecdsa_keygen_data_3.json](/protocols/cggmp/test/_keygen_fixtures/threshold/ecdsa_keygen_data_3.json) | JSON | 1 | 0 | 0 | 1 |
| [protocols/cggmp/test/_keygen_fixtures/threshold/ecdsa_keygen_data_4.json](/protocols/cggmp/test/_keygen_fixtures/threshold/ecdsa_keygen_data_4.json) | JSON | 1 | 0 | 0 | 1 |
| [protocols/cggmp/test/_keygen_fixtures/threshold/eddsa_keygen_data_0.json](/protocols/cggmp/test/_keygen_fixtures/threshold/eddsa_keygen_data_0.json) | JSON | 20 | 0 | 1 | 21 |
| [protocols/cggmp/test/_keygen_fixtures/threshold/eddsa_keygen_data_1.json](/protocols/cggmp/test/_keygen_fixtures/threshold/eddsa_keygen_data_1.json) | JSON | 20 | 0 | 1 | 21 |
| [protocols/cggmp/test/_keygen_fixtures/threshold/eddsa_keygen_data_2.json](/protocols/cggmp/test/_keygen_fixtures/threshold/eddsa_keygen_data_2.json) | JSON | 20 | 0 | 1 | 21 |
| [protocols/cggmp/test/_presign_fixtures/non_threshold/ecdsa_presign_data_0.json](/protocols/cggmp/test/_presign_fixtures/non_threshold/ecdsa_presign_data_0.json) | JSON | 10 | 0 | 1 | 11 |
| [protocols/cggmp/test/_presign_fixtures/non_threshold/ecdsa_presign_data_1.json](/protocols/cggmp/test/_presign_fixtures/non_threshold/ecdsa_presign_data_1.json) | JSON | 10 | 0 | 1 | 11 |
| [protocols/cggmp/test/_presign_fixtures/non_threshold/ecdsa_presign_data_2.json](/protocols/cggmp/test/_presign_fixtures/non_threshold/ecdsa_presign_data_2.json) | JSON | 10 | 0 | 1 | 11 |
| [protocols/cggmp/test/_presign_fixtures/non_threshold/eddsa_presign_data_0.json](/protocols/cggmp/test/_presign_fixtures/non_threshold/eddsa_presign_data_0.json) | JSON | 6 | 0 | 1 | 7 |
| [protocols/cggmp/test/_presign_fixtures/non_threshold/eddsa_presign_data_1.json](/protocols/cggmp/test/_presign_fixtures/non_threshold/eddsa_presign_data_1.json) | JSON | 6 | 0 | 1 | 7 |
| [protocols/cggmp/test/_presign_fixtures/non_threshold/eddsa_presign_data_2.json](/protocols/cggmp/test/_presign_fixtures/non_threshold/eddsa_presign_data_2.json) | JSON | 6 | 0 | 1 | 7 |
| [protocols/cggmp/test/_presign_fixtures/threshold/ecdsa_presign_data_0.json](/protocols/cggmp/test/_presign_fixtures/threshold/ecdsa_presign_data_0.json) | JSON | 10 | 0 | 1 | 11 |
| [protocols/cggmp/test/_presign_fixtures/threshold/ecdsa_presign_data_1.json](/protocols/cggmp/test/_presign_fixtures/threshold/ecdsa_presign_data_1.json) | JSON | 10 | 0 | 1 | 11 |
| [protocols/cggmp/test/_presign_fixtures/threshold/ecdsa_presign_data_2.json](/protocols/cggmp/test/_presign_fixtures/threshold/ecdsa_presign_data_2.json) | JSON | 10 | 0 | 1 | 11 |
| [protocols/cggmp/test/_presign_fixtures/threshold/eddsa_presign_data_0.json](/protocols/cggmp/test/_presign_fixtures/threshold/eddsa_presign_data_0.json) | JSON | 6 | 0 | 1 | 7 |
| [protocols/cggmp/test/_presign_fixtures/threshold/eddsa_presign_data_1.json](/protocols/cggmp/test/_presign_fixtures/threshold/eddsa_presign_data_1.json) | JSON | 6 | 0 | 1 | 7 |
| [protocols/cggmp/test/_presign_fixtures/threshold/eddsa_presign_data_2.json](/protocols/cggmp/test/_presign_fixtures/threshold/eddsa_presign_data_2.json) | JSON | 6 | 0 | 1 | 7 |
| [protocols/cggmp/test/utils.go](/protocols/cggmp/test/utils.go) | Go | 26 | 8 | 5 | 39 |
| [protocols/frost/presign/local_party.go](/protocols/frost/presign/local_party.go) | Go | 91 | 7 | 21 | 119 |
| [protocols/frost/presign/local_party_test.go](/protocols/frost/presign/local_party_test.go) | Go | 164 | 11 | 36 | 211 |
| [protocols/frost/presign/round_1.go](/protocols/frost/presign/round_1.go) | Go | 79 | 2 | 16 | 97 |
| [protocols/frost/presign/round_final.go](/protocols/frost/presign/round_final.go) | Go | 46 | 2 | 15 | 63 |
| [protocols/frost/presign/rounds.go](/protocols/frost/presign/rounds.go) | Go | 74 | 6 | 15 | 95 |
| [protocols/frost/presign/save_data.go](/protocols/frost/presign/save_data.go) | Go | 65 | 4 | 11 | 80 |
| [protocols/frost/presign/test_utils.go](/protocols/frost/presign/test_utils.go) | Go | 58 | 0 | 9 | 67 |
| [protocols/frost/sign/local_party.go](/protocols/frost/sign/local_party.go) | Go | 129 | 11 | 29 | 169 |
| [protocols/frost/sign/local_party_test.go](/protocols/frost/sign/local_party_test.go) | Go | 198 | 16 | 44 | 258 |
| [protocols/frost/sign/messages.go](/protocols/frost/sign/messages.go) | Go | 74 | 4 | 14 | 92 |
| [protocols/frost/sign/round_1.go](/protocols/frost/sign/round_1.go) | Go | 75 | 2 | 15 | 92 |
| [protocols/frost/sign/round_2.go](/protocols/frost/sign/round_2.go) | Go | 127 | 4 | 33 | 164 |
| [protocols/frost/sign/round_final.go](/protocols/frost/sign/round_final.go) | Go | 79 | 3 | 21 | 103 |
| [protocols/frost/sign/rounds.go](/protocols/frost/sign/rounds.go) | Go | 89 | 6 | 15 | 110 |
| [protocols/frost/sign/sign.pb.go](/protocols/frost/sign/sign.pb.go) | Go | 179 | 11 | 27 | 217 |
| [protocols/frost/sign/sign.proto](/protocols/frost/sign/sign.proto) | Protocol Buffers | 16 | 0 | 3 | 19 |
| [protocols/frost/sign/utils.go](/protocols/frost/sign/utils.go) | Go | 91 | 7 | 26 | 124 |
| [protocols/frost/signing/local_party.go](/protocols/frost/signing/local_party.go) | Go | 132 | 10 | 25 | 167 |
| [protocols/frost/signing/local_party_test.go](/protocols/frost/signing/local_party_test.go) | Go | 204 | 16 | 46 | 266 |
| [protocols/frost/signing/round_1.go](/protocols/frost/signing/round_1.go) | Go | 139 | 5 | 32 | 176 |
| [protocols/frost/signing/round_final.go](/protocols/frost/signing/round_final.go) | Go | 80 | 3 | 21 | 104 |
| [protocols/frost/signing/rounds.go](/protocols/frost/signing/rounds.go) | Go | 87 | 6 | 15 | 108 |
| [protocols/frost/signing/utils.go](/protocols/frost/signing/utils.go) | Go | 91 | 7 | 26 | 124 |
| [protocols/frost/test/_presign_fixtures/non_threshold/eddsa_presign_data_0.json](/protocols/frost/test/_presign_fixtures/non_threshold/eddsa_presign_data_0.json) | JSON | 34 | 0 | 1 | 35 |
| [protocols/frost/test/_presign_fixtures/non_threshold/eddsa_presign_data_1.json](/protocols/frost/test/_presign_fixtures/non_threshold/eddsa_presign_data_1.json) | JSON | 34 | 0 | 1 | 35 |
| [protocols/frost/test/_presign_fixtures/non_threshold/eddsa_presign_data_2.json](/protocols/frost/test/_presign_fixtures/non_threshold/eddsa_presign_data_2.json) | JSON | 34 | 0 | 1 | 35 |
| [protocols/frost/test/_presign_fixtures/threshold/eddsa_presign_data_0.json](/protocols/frost/test/_presign_fixtures/threshold/eddsa_presign_data_0.json) | JSON | 34 | 0 | 1 | 35 |
| [protocols/frost/test/_presign_fixtures/threshold/eddsa_presign_data_1.json](/protocols/frost/test/_presign_fixtures/threshold/eddsa_presign_data_1.json) | JSON | 34 | 0 | 1 | 35 |
| [protocols/frost/test/_presign_fixtures/threshold/eddsa_presign_data_2.json](/protocols/frost/test/_presign_fixtures/threshold/eddsa_presign_data_2.json) | JSON | 34 | 0 | 1 | 35 |
| [protocols/utils/key_derivation.go](/protocols/utils/key_derivation.go) | Go | 42 | 1 | 8 | 51 |
| [protocols/utils/key_updater.go](/protocols/utils/key_updater.go) | Go | 36 | 0 | 11 | 47 |
| [protocols/utils/prepare_sign.go](/protocols/utils/prepare_sign.go) | Go | 74 | 9 | 8 | 91 |
| [tss/curve.go](/tss/curve.go) | Go | 55 | 14 | 18 | 87 |
| [tss/error.go](/tss/error.go) | Go | 31 | 6 | 12 | 49 |
| [tss/message.go](/tss/message.go) | Go | 114 | 31 | 25 | 170 |
| [tss/message.pb.go](/tss/message.pb.go) | Go | 244 | 26 | 34 | 304 |
| [tss/params.go](/tss/params.go) | Go | 129 | 10 | 31 | 170 |
| [tss/party.go](/tss/party.go) | Go | 146 | 17 | 21 | 184 |
| [tss/party_id.go](/tss/party_id.go) | Go | 108 | 19 | 23 | 150 |
| [tss/peers.go](/tss/peers.go) | Go | 15 | 5 | 6 | 26 |
| [tss/round.go](/tss/round.go) | Go | 12 | 5 | 3 | 20 |
| [tss/wire.go](/tss/wire.go) | Go | 35 | 6 | 6 | 47 |

[Summary](results.md) / Details / [Diff Summary](diff.md) / [Diff Details](diff-details.md)