import * as ed25519 from "@noble/ed25519";
import { secp256r1 } from "@noble/curves/p256";
import { secp384r1 } from "@noble/curves/p384";
import { secp521r1 } from "@noble/curves/p521";
import { ed448, x448 } from "@noble/curves/ed448";
import { sha384, sha512 } from "@noble/hashes/sha512";
import { Aes128Gcm, Aes256Gcm, CipherSuite, DhkemP256HkdfSha256, DhkemP384HkdfSha384, DhkemP521HkdfSha512, HkdfSha256, HkdfSha384, HkdfSha512, type AeadInterface, type KdfInterface, type KemInterface } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { DhkemX448HkdfSha512 } from "@hpke/dhkem-x448";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { CipherSuiteType } from "./Enums";
import Uint16 from "./types/Uint16";
import { sha256 } from "@noble/hashes/sha256";
import { x25519 } from "@noble/curves/ed25519";

// required polyfills
ed25519.etc.sha512Sync = (...m) => sha512(ed25519.etc.concatBytes(...m))

interface CryptoImplementation {
    signAsync(key: Uint8Array, message: Uint8Array): Promise<Uint8Array>;
    verifyAsync(key: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean>;
    generateKeyPair(): Promise<{ privateKey: Uint8Array, publicKey: Uint8Array }>;
    generateSigningKeyPair(): Promise<{ privateKey: Uint8Array, publicKey: Uint8Array }>;
}

function GenerateKeyPairInternal(curve: typeof x25519 | typeof ed25519 | typeof secp256r1 | typeof secp384r1 | typeof secp521r1 | typeof ed448 | typeof x448) {
    const pk = curve.utils.randomPrivateKey();
    return {
        privateKey: pk,
        publicKey: curve.getPublicKey(pk)
    }
}

const CryptoImplementations = <const>{
    "ed25519": {
        async signAsync(key, message) {
            return ed25519.sign(message, key);
        },
        async verifyAsync(key, message, signature) {
            return ed25519.verify(signature, message, key);
        },
        async generateKeyPair() {
            return GenerateKeyPairInternal(x25519);
        },
        async generateSigningKeyPair() {
            return GenerateKeyPairInternal(ed25519);
        }
    },
    "ed448": {
        async signAsync(key, message) {
            return ed448.sign(message, key);
        },
        async verifyAsync(key, message, signature) {
            return ed448.verify(signature, message, key);
        },
        async generateKeyPair() {
            return GenerateKeyPairInternal(x448);
        },
        async generateSigningKeyPair() {
            return GenerateKeyPairInternal(ed448);
        },
    },
    "secp256r1": {
        async signAsync(key, message) {
            return secp256r1.sign(message, key).toCompactRawBytes();
        },
        async verifyAsync(key, message, signature) {
            return secp256r1.verify(signature, message, key);
        },
        async generateKeyPair() {
            return GenerateKeyPairInternal(secp256r1);
        },
        async generateSigningKeyPair() {
            return GenerateKeyPairInternal(secp256r1);
        }
    },
    "secp384r1": {
        async signAsync(key, message) {
            return secp384r1.sign(message, key).toCompactRawBytes();
        },
        async verifyAsync(key, message, signature) {
            return secp384r1.verify(signature, message, key);
        },
        async generateKeyPair() {
            return GenerateKeyPairInternal(secp384r1);
        },
        async generateSigningKeyPair() {
            return GenerateKeyPairInternal(secp384r1);
        },
    },
    "secp521r1": {
        async signAsync(key, message) {
            return secp521r1.sign(message, key).toCompactRawBytes();
        },
        async verifyAsync(key, message, signature) {
            return secp521r1.verify(signature, message, key);
        },
        async generateKeyPair() {
            return GenerateKeyPairInternal(secp521r1);
        },
        async generateSigningKeyPair() {
            return GenerateKeyPairInternal(secp521r1);
        },
    },
} satisfies Record<string, CryptoImplementation>;

function GetCryptoImpl(cipherSuite: CipherSuiteType): CryptoImplementation {
    switch (cipherSuite) {
        case CipherSuiteType.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519:
        case CipherSuiteType.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519:
            return CryptoImplementations["ed25519"];
        case CipherSuiteType.MLS_128_DHKEMP256_AES128GCM_SHA256_P256:
            return CryptoImplementations["secp256r1"];
        case CipherSuiteType.MLS_256_DHKEMP384_AES256GCM_SHA384_P384:
            return CryptoImplementations["secp384r1"];
        case CipherSuiteType.MLS_256_DHKEMP521_AES256GCM_SHA512_P521:
            return CryptoImplementations["secp521r1"];
        case CipherSuiteType.MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448:
        case CipherSuiteType.MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448:
            return CryptoImplementations["ed448"];
        default:
            throw new Error("Unsupported cipher suite");
    }
}

function GetHashFunction(cipherSuite: CipherSuiteType): typeof sha256 | typeof sha384 | typeof sha512 {
    switch (cipherSuite) {
        case CipherSuiteType.MLS_128_DHKEMP256_AES128GCM_SHA256_P256:
        case CipherSuiteType.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519:
        case CipherSuiteType.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519:
            return sha256;
        case CipherSuiteType.MLS_256_DHKEMP384_AES256GCM_SHA384_P384:
            return sha384;
        case CipherSuiteType.MLS_256_DHKEMP521_AES256GCM_SHA512_P521:
        case CipherSuiteType.MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448:
        case CipherSuiteType.MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448:
            return sha512;
        default:
            throw new Error("Unsupported cipher suite");
    }
}

function DecodeCipherSuiteType(value: number): CipherSuite {
    if (value <= 0x0000 || value > 0xFFFF) {
        throw new RangeError("Invalid cipher suite type");
    }
    let kem: KemInterface | undefined = undefined;
    let kdf: KdfInterface | undefined = undefined;
    let aead: AeadInterface | undefined = undefined;
    // set kem
    switch (value) {
        case CipherSuiteType.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519:
        case CipherSuiteType.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519:
            kem = new DhkemX25519HkdfSha256();
            break;
        case CipherSuiteType.MLS_128_DHKEMP256_AES128GCM_SHA256_P256:
            kem = new DhkemP256HkdfSha256();
            break;
        case CipherSuiteType.MLS_256_DHKEMP384_AES256GCM_SHA384_P384:
            kem = new DhkemP384HkdfSha384();
            break;
        case CipherSuiteType.MLS_256_DHKEMP521_AES256GCM_SHA512_P521:
            kem = new DhkemP521HkdfSha512();
            break;
        case CipherSuiteType.MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448:
            kem = new DhkemX448HkdfSha512();
            break;
        case CipherSuiteType.MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448:
            kem = new DhkemX448HkdfSha512();
            break;
    }
    // set kdf
    switch (value) {
        case CipherSuiteType.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519:
        case CipherSuiteType.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519:
        case CipherSuiteType.MLS_128_DHKEMP256_AES128GCM_SHA256_P256:
            kdf = new HkdfSha256();
            break;
        case CipherSuiteType.MLS_256_DHKEMP384_AES256GCM_SHA384_P384:
            kdf = new HkdfSha384();
            break;
        case CipherSuiteType.MLS_256_DHKEMP521_AES256GCM_SHA512_P521:
        case CipherSuiteType.MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448:
        case CipherSuiteType.MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448:
            kdf = new HkdfSha512();
            break;
    }
    // set aead
    switch (value) {
        case CipherSuiteType.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519:
        case CipherSuiteType.MLS_128_DHKEMP256_AES128GCM_SHA256_P256:
            aead = new Aes128Gcm();
            break;
        case CipherSuiteType.MLS_256_DHKEMP384_AES256GCM_SHA384_P384:
        case CipherSuiteType.MLS_256_DHKEMP521_AES256GCM_SHA512_P521:
        case CipherSuiteType.MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448:
            aead = new Aes256Gcm();
            break;
        case CipherSuiteType.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519:
        case CipherSuiteType.MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448:
            aead = new Chacha20Poly1305();
            break;
    }

    if (kem === undefined || kdf === undefined || aead === undefined) {
        throw new Error("Invalid cipher suite type");
    }

    const ciphersuite = new CipherSuite({
        kem,
        kdf,
        aead
    })
    return ciphersuite;
}

function GetAllCipherSuites() {
    return [
        CipherSuiteType.MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        CipherSuiteType.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        CipherSuiteType.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        CipherSuiteType.MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
        CipherSuiteType.MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
        CipherSuiteType.MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
        CipherSuiteType.MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
    ]
}

const labelHeader = new TextEncoder().encode("MLS 1.0 ");

function SignWithLabel(key: Uint8Array, label: Uint8Array, content: Uint8Array, cipherSuite: CipherSuiteType) {
    const crypto = GetCryptoImpl(cipherSuite);
    const finalContent = new Uint8Array(labelHeader.length + label.length + content.length);
    finalContent.set(labelHeader);
    finalContent.set(label, labelHeader.length);
    finalContent.set(content, labelHeader.length + label.length);
    return crypto.signAsync(key, finalContent);
}

function VerifyWithLabel(key: Uint8Array, label: Uint8Array, content: Uint8Array, signature: Uint8Array, cipherSuite: CipherSuiteType) {
    const crypto = GetCryptoImpl(cipherSuite);
    const finalContent = new Uint8Array(labelHeader.length + label.length + content.length);
    finalContent.set(labelHeader);
    finalContent.set(label, labelHeader.length);
    finalContent.set(content, labelHeader.length + label.length);
    return crypto.verifyAsync(key, finalContent, signature);
}

function GenerateKeyPair(cipherSuite: CipherSuiteType) {
    return GetCryptoImpl(cipherSuite).generateKeyPair();
}

function GenerateSigningKeyPair(cipherSuite: CipherSuiteType) {
    return GetCryptoImpl(cipherSuite).generateSigningKeyPair();
}

async function EncryptWithLabel(key: Uint8Array, label: Uint8Array, context: Uint8Array, plaintext: Uint8Array, cipherSuite: CipherSuiteType) {
    const suite = DecodeCipherSuiteType(cipherSuite);
    const finalContext = new Uint8Array(labelHeader.length + label.length + context.length);
    finalContext.set(labelHeader);
    finalContext.set(label, labelHeader.length);
    finalContext.set(context, labelHeader.length + label.length);
    return suite.seal({
        recipientPublicKey: await suite.kem.deserializePublicKey(key.buffer as ArrayBuffer),
        info: finalContext.buffer as ArrayBuffer
    }, plaintext.buffer as ArrayBuffer).then(r => {
        return {
            ciphertext: new Uint8Array(r.ct),
            encKey: new Uint8Array(r.enc),
        }
    });
}

async function DecryptWithLabel(key: Uint8Array, encKey: Uint8Array, label: Uint8Array, context: Uint8Array, ciphertext: Uint8Array, cipherSuite: CipherSuiteType) {
    const suite = DecodeCipherSuiteType(cipherSuite);
    const finalContext = new Uint8Array(labelHeader.length + label.length + context.length);
    finalContext.set(labelHeader);
    finalContext.set(label, labelHeader.length);
    finalContext.set(context, labelHeader.length + label.length);
    return suite.open({
        recipientKey: await suite.kem.deserializePublicKey(key.buffer as ArrayBuffer),
        info: finalContext.buffer as ArrayBuffer,
        enc: encKey.buffer as ArrayBuffer
    }, ciphertext.buffer as ArrayBuffer).then(r => new Uint8Array(r));
}

async function ExpandWithLabel(secret: Uint8Array, label: Uint8Array, context: Uint8Array, length: Uint16, cipherSuite: CipherSuiteType) {
    const suite = DecodeCipherSuiteType(cipherSuite);
    const finalLabel = new Uint8Array(2 + labelHeader.length + label.length + context.length);
    finalLabel.set(length.encode());
    finalLabel.set(labelHeader, 2);
    finalLabel.set(label, 2 + labelHeader.length);
    finalLabel.set(context, 2 + labelHeader.length + label.length);
    const r = await suite.kdf.expand(secret.buffer as ArrayBuffer, finalLabel.buffer as ArrayBuffer, length.value);
    return new Uint8Array(r);
}

async function Extract(key: Uint8Array, salt: Uint8Array, cipherSuite: CipherSuiteType) {
    const suite = DecodeCipherSuiteType(cipherSuite);
    const r = await suite.kdf.extract(salt.buffer as ArrayBuffer, key.buffer as ArrayBuffer);
    return new Uint8Array(r);
}

function DeriveSecret(secret: Uint8Array, label: Uint8Array, cipherSuite: CipherSuiteType) {
    const suite = DecodeCipherSuiteType(cipherSuite);
    return ExpandWithLabel(secret, label, new Uint8Array(0), Uint16.from(suite.kdf.hashSize), cipherSuite);
}

async function Hash(message: Uint8Array, cipherSuite: CipherSuiteType) {
    const hashFunction = GetHashFunction(cipherSuite);
    return hashFunction(message)
}

function ArraysEqual(a: Uint8Array, b: Uint8Array) {
    if (a.length !== b.length) {
        return false;
    }
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            return false;
        }
    }
    return true;
}

function GetCurrentTime() {
    return BigInt(Math.floor(Date.now() / 1000))
}

export { SignWithLabel, VerifyWithLabel, GenerateKeyPair, DecodeCipherSuiteType, EncryptWithLabel, DecryptWithLabel, ExpandWithLabel, DeriveSecret, Hash, Extract, ArraysEqual, GetAllCipherSuites, GetCurrentTime, GenerateSigningKeyPair };