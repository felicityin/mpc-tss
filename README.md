# Introduction

This repo is inspired by [alice](https://github.com/getamis/alice), [tss-lib](https://github.com/bnb-chain/tss-lib), [cggmp21](https://github.com/dfns/cggmp21) and [multi-party-sig](https://github.com/taurushq-io/multi-party-sig).

This repo is a Go implementation of multi-party {t,n}-threshold ECDSA (Elliptic Curve Digital Signature Algorithm) based on [CGGMP21](https://eprint.iacr.org/2021/060) and EdDSA (Edwards-curve Digital Signature Algorithm) based on [FROST](https://eprint.iacr.org/2020/852.pdf).

[CGGMP21](https://eprint.iacr.org/2021/060) is a state-of-art ECDSA TSS protocol that supports 1-round signing (requires preprocessing), identifiable abort, provides two signing protocols (3+1 and 5+1 rounds with different complexity of abort identification) and key refresh protocol out of the box.

For [CGGMP21](https://eprint.iacr.org/2021/060), this repo implements:

- Threshold (i.e., t-out-of-n) and non-threshold (i.e., n-out-of-n) key generation
- (3+1)-round general threshold and non-threshold signing
- Auxiliary info generation protocol
- HD-wallets support based on slip10 standard (compatible with bip32)

This repo does not (currently) support:

- Key refresh
- Identifiable abort
- The (5+1)-round signing protocol

[FROST](https://eprint.iacr.org/2020/852.pdf) is a state-of-art EdDSA TSS protocol that can be used as either a two-round protocol, or optimized to a single-round signing protocol with a pre-processing stage.

For [FROST](https://eprint.iacr.org/2020/852.pdf), this repo implements:

- (1+1)-round general threshold and non-threshold signing
- HD-wallets support based on slip10 standard (compatible with bip32)

# Examples

## CGGMP21

### ECDSA

##### Non-Threshold

- [keygen](https://github.com/felicityin/mpc-tss/blob/main/protocols/cggmp/keygen/non_threshold/local_party_test.go#L35)
- [auxiliary](https://github.com/felicityin/mpc-tss/blob/main/protocols/cggmp/auxiliary/local_party_test.go)
- [sign](https://github.com/felicityin/mpc-tss/blob/main/protocols/cggmp/ecdsa/sign/local_party_test.go#L39)
- [pre-signing](https://github.com/felicityin/mpc-tss/blob/main/protocols/cggmp/ecdsa/presign/local_party_test.go#L37)
- [signing](https://github.com/felicityin/mpc-tss/blob/main/protocols/cggmp/ecdsa/signing/local_party_test.go#L39)

##### Threshold

- [keygen](https://github.com/felicityin/mpc-tss/blob/main/protocols/cggmp/keygen/threshold/local_party_test.go#L39)
- [auxiliary](https://github.com/felicityin/mpc-tss/blob/main/protocols/cggmp/auxiliary/local_party_test.go)
- [sign](https://github.com/felicityin/mpc-tss/blob/main/protocols/cggmp/ecdsa/sign/local_party_test.go#L143)
- [pre-signing](https://github.com/felicityin/mpc-tss/blob/main/protocols/cggmp/ecdsa/presign/local_party_test.go#L121)
- [signing](https://github.com/felicityin/mpc-tss/blob/main/protocols/cggmp/ecdsa/signing/local_party_test.go#L143)

### EdDSA

##### Non-Threshold

- [keygen](https://github.com/felicityin/mpc-tss/blob/main/protocols/cggmp/keygen/non_threshold/local_party_test.go#L39)
- [sign](https://github.com/felicityin/mpc-tss/blob/main/protocols/cggmp/eddsa/sign/local_party_test.go#L40)
- [pre-signing](https://github.com/felicityin/mpc-tss/blob/main/protocols/cggmp/eddsa/presign/local_party_test.go#L37)
- [signing](https://github.com/felicityin/mpc-tss/blob/main/protocols/cggmp/eddsa/signing/local_party_test.go#L38)

##### Threshold

- [keygen](https://github.com/felicityin/mpc-tss/blob/main/protocols/cggmp/keygen/threshold/local_party_test.go#L43)
- [sign](https://github.com/felicityin/mpc-tss/blob/main/protocols/cggmp/eddsa/sign/local_party_test.go#L155)
- [pre-signing](https://github.com/felicityin/mpc-tss/blob/main/protocols/cggmp/eddsa/presign/local_party_test.go#L120)
- [signing](https://github.com/felicityin/mpc-tss/blob/main/protocols/cggmp/eddsa/signing/local_party_test.go#L153)

## FROST

### EdDSA

##### Non-Threshold

- [keygen](https://github.com/felicityin/mpc-tss/blob/main/protocols/cggmp/keygen/non_threshold/local_party_test.go#L39)
- [sign](https://github.com/felicityin/mpc-tss/blob/main/protocols/frost/sign/local_party_test.go#L39)
- [pre-signing](https://github.com/felicityin/mpc-tss/blob/main/protocols/frost/presign/local_party_test.go#L36)
- [signing](https://github.com/felicityin/mpc-tss/blob/main/protocols/frost/signing/local_party_test.go#L40)

##### Threshold

- [keygen](https://github.com/felicityin/mpc-tss/blob/main/protocols/cggmp/keygen/threshold/local_party_test.go#L43)
- [sign](https://github.com/felicityin/mpc-tss/blob/main/protocols/frost/sign/local_party_test.go#L150)
- [pre-signing](https://github.com/felicityin/mpc-tss/blob/main/protocols/frost/presign/local_party_test.go#L111)
- [signing](https://github.com/felicityin/mpc-tss/blob/main/protocols/frost/signing/local_party_test.go#L155)
