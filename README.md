# prople/crypto

> **WARNING**
>
> We have a breaking changes start version `0.3.0`, please use at least this version for a better API library structure

This library provides multiple core algorithms :

- `ECDH / X25519` used for digital signature and key agreement
- `EdDSA / ED25519` used for digital signature and account management
- `AEAD (Authenticated Encryption with Associated Data)` used for standard encryption keys
    - `ChaCha20Poly1305` : Used as main encryption algorithm
- `Argon2` used as main `KDF (Key Deriviation Function)` to hash the password
- `Blake3` used as main hash function when hashing generated shared secret key from `ECDH` 
- `Chacha RNG` used as main random generator

Notes:

- The `ECDH`, the generated key secret, will using bytes and converted to hex.  
- The `EdDSA`, the generated private key, will using bytes and converted to standard `PEM` format.

> **INFO**
>
> All of these cryptographic algorithms used to fulfill `Prople` project's needs
> It's still possible to use all of these algorithms, as long as your project has a similarity with `Prople`

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

## Installation

```toml
[dependencies]
prople-crypto = {version = "0.3.0"}
```

## Usages

### ECDH 

Generate `KeyPair` :

```no_run
use prople_crypto::ecdh::keypair::KeyPair;

let keypair = KeyPair::generate();

// get public key
let pubkey = keypair.pub_key();
```

Generate shared secret :

> **INFO**
>
> To generate shared secret, both parties must exchange their public keys

```no_run
use prople_crypto::ecdh::keypair::KeyPair;

// assumed alice and bob as parties
let keypair_alice = KeyPair::generate();
let keypair_bob = KeyPair::generate();

let pubkey_alice = keypair_alice.pub_key();
let pubkey_bob = keypair_bob.pub_key();
        
let public_alice_hex = pubkey_alice.to_hex();
let public_bob_hex = pubkey_bob.to_hex();

// alice need bob's public key
let secret_alice = keypair_alice.secret(&public_bob_hex);

// bob need alice's public key
let secret_bob = keypair_bob.secret(&public_alice_hex);

// hash the generated secret using `BLAKE3`        
let shared_secret_alice_blake3 = secret_alice.to_blake3();
let shared_secret_bob_blake3 = secret_bob.to_blake3();
```

Please explore our API library documentation for the [`ecdh`] module for more detail explanation and available public methods

### EDDSA

Generate `KeyPair`

```no_run
use prople_crypto::eddsa::keypair::KeyPair;

let keypair1 = KeyPair::generate();

// generate PEM value
let private_key_pem: Result<String, EddsaError> = keypair.priv_key().to_pem();

// generate from PEM
ley keypair2 = KeyPair::from_pem(private_key_pem.unwrap());
```

Generate digital signature

```no_run
use prople_crypto::eddsa::keypair::KeyPair;

let keypair = KeyPair::generate();
let signature = keypair.signature("my message".as_bytes());
let digital_signature = signature.to_hex();
```

Please explore our API library documentation for the [`eddsa`] module for more detail explanation and available public methods

### KeySecure

Our [`keysecure::KeySecure`] format actually try to following strategy and pattern from `Ethereum KeyStore`.

Example generate `KeySecure` from `ECDH` keypair

```no_run
use prople_crypto::ecdh::keypair::KeyPair;

let keypair = KeyPair::generate();
let keysecure: Result<KeySecure, KeySecureError> = keypair.to_keysecure("password".to_string);
```

> **INFO**
>
> Both `ECDH` and `EDDSA` generated keypairs already implement `ToKeySecure` trait behavior, so both of this
> generated data will use same method to generate it's `KeySecure` format