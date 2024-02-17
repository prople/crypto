# prople/agent/crypto

The crypto library used by 

- `prople/agent/account`
- `prople/agent/did`

This library provides multiple core algorithms :

- `ECDSA / X25519` used for digital signature and key agreement
- `EdDSA / ED25519` used for digital signature and account management
- `AEAD (Authenticated Encryption with Associated Data)` used for standard encryption keys
    - `ChaCha20Poly1305` : Used as main encryption algorithm
- `Argon2` used as main `KDF (Key Deriviation Function)` to hash the password
- `Blake3` used as main hash function when hashing generated shared secret key from `ECDSA` 
- `Chacha RNG` used as main random generator

For the `ECDSA`, the generated key secret, will using bytes and converted to hex.
For the `EdDSA`, the generated private key, will using bytes and converted to standard `PEM` format.

All of these generated keys will be put and encrypted into `KeySecure` format following `Ethereum KeyStore` strategy, which means the generated json will be stored in disk. Example json output:

```json
{
  "id": "ea433df6-6fcc-49e5-a535-20704c18e126",
  "context": "X25519",
  "crypto": {
    "cipher": "xchacha20poly1305",
    "cipherText": "712cd6261ea338100906c8c017d640d37d27bd58f91b1bf8f809a5a02a73e4e3b80002910b678f847b77e533ef6e1f29",
    "cipherParams": {
      "nonce": "f7e1d00e48a538936b3d48eeebc3847057acba24edb06f9b"
    },
    "kdf": "argon2",
    "kdfParams": {
      "params": {
        "m_cost": 19456,
        "t_cost": 2,
        "p_cost": 1,
        "outputLen": 32
      },
      "salt": "5Qm7QPATRUE6czNKJWODtg"
    }
  }
}
```

> The `ECDSA` algorithm described on this library will not be used on `P2P` connection, since the `prople/agent` using `rust-libp2p` that already have its own key agreement mechanism for its `Noice Protocol` 