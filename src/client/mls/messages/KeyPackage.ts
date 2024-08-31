import type { Credential } from "../Credential";
import { GenerateKeyPair, SignWithLabel } from "../CryptoHelper";
import { Decoder, Encoder } from "../Encoding";
import { ProtocolVersion, type CipherSuiteType, type ExtensionType } from "../Enums";
import InvalidObjectError from "../errors/InvalidObjectError";
import { DecodeExtension, EncodeExtension, type Extension } from "../Extension";
import { DecodeLeafNode, EncodeLeafNode, GenerateLeafNode, IsLeafNodeKeyPackage, type LeafNodeKeyPackage } from "../RatchetTree";
import Uint16 from "../types/Uint16";

interface KeyPackage {
    version: ProtocolVersion;
    cipher_suite: CipherSuiteType;
    init_key: Uint8Array;
    leaf_node: LeafNodeKeyPackage;
    extensions: Extension<ExtensionType>[];
    signature?: Uint8Array;
}

function IsKeyPackage(object: unknown): object is KeyPackage {
    return (
        typeof object === "object" &&
        object !== null &&
        "version" in object &&
        typeof object.version === "number" &&
        "cipher_suite" in object &&
        typeof object.cipher_suite === "number" &&
        "init_key" in object &&
        object.init_key instanceof Uint8Array &&
        "leaf_node" in object &&
        IsLeafNodeKeyPackage(object.leaf_node) &&
        "extensions" in object &&
        object.extensions instanceof Array &&
        (("signature" in object && object.signature instanceof Uint8Array) || !("signature" in object))
    );
}

function ConstructKeyPackageSignatureData(keyPackage: KeyPackage) {
    const encoder = new Encoder();
    encoder.writeUint(Uint16.from(keyPackage.version));
    encoder.writeUint(Uint16.from(keyPackage.cipher_suite));
    encoder.writeUint8Array(keyPackage.init_key);
    encoder.writeUint8Array(EncodeLeafNode(keyPackage.leaf_node), false);
    return encoder.flush();
}

function EncodeKeyPackage(keyPackage: KeyPackage) {
    if (keyPackage.signature == null) {
        throw new Error("Signature is missing");
    }
    const encoder = new Encoder();
    encoder.writeUint(Uint16.from(keyPackage.version));
    encoder.writeUint(Uint16.from(keyPackage.cipher_suite));
    encoder.writeUint8Array(keyPackage.init_key);
    encoder.writeUint8Array(EncodeLeafNode(keyPackage.leaf_node), false);
    encoder.writeUint(Uint16.from(keyPackage.extensions.length));
    keyPackage.extensions.forEach((e) => encoder.writeUint8Array(EncodeExtension(e), false));
    encoder.writeUint8Array(keyPackage.signature);
    return encoder.flush();
}

function DecodeKeyPackage(decoder: Decoder): KeyPackage {
    const version = decoder.readUint16().value;
    const cipher_suite = decoder.readUint16().value;
    const init_key = decoder.readUint8Array();
    const leaf_node = DecodeLeafNode(decoder);
    const extensionsLength = decoder.readUint16().value;
    const extensions: Extension<ExtensionType>[] = [];
    for (let i = 0; i < extensionsLength; i++) {
        extensions.push(DecodeExtension(decoder));
    }
    const signature = decoder.readUint8Array();
    const keyPackage = {
        version,
        cipher_suite,
        init_key,
        leaf_node,
        extensions,
        signature
    };
    if (!IsKeyPackage(keyPackage)) {
        throw new InvalidObjectError("Invalid key package");
    }
    return keyPackage;
}

interface GenerateKeyPackageParams {
    cipherSuite: CipherSuiteType;
    signingKeyPriv: Uint8Array;
    signingKeyPub: Uint8Array;
    credential: Credential;
    extensions: Extension<ExtensionType.application_id>[];
    validFor?: bigint;
    version?: ProtocolVersion;
}
async function GenerateKeyPackage(
    params: GenerateKeyPackageParams
): Promise<{ keyPackage: KeyPackage; initKeyPrivate: Uint8Array; leafNodePrivate: Uint8Array }> {
    const { cipherSuite, signingKeyPriv, signingKeyPub, credential, extensions, validFor } = params;
    const initKeyPair = await GenerateKeyPair(cipherSuite);
    // create the leaf node
    const leafNode = await GenerateLeafNode({ cipherSuite, signingKeyPriv, signingKeyPub, credential, extensions, validFor });
    // create the key package
    const keyPackage = {
        version: params.version ?? ProtocolVersion.mls10,
        cipher_suite: cipherSuite,
        init_key: initKeyPair.publicKey,
        leaf_node: leafNode.node,
        extensions,
        signature: new Uint8Array(0)
    } satisfies KeyPackage;
    const keyPackageSignatureData = ConstructKeyPackageSignatureData(keyPackage);
    const keyPackageSignature = await SignWithLabel(
        signingKeyPriv,
        new TextEncoder().encode("KeyPackageTBS"),
        keyPackageSignatureData,
        cipherSuite
    );
    keyPackage.signature = keyPackageSignature;
    return { keyPackage, initKeyPrivate: initKeyPair.privateKey, leafNodePrivate: leafNode.nodePrivateKey };
}

export { ConstructKeyPackageSignatureData, DecodeKeyPackage, EncodeKeyPackage, IsKeyPackage, GenerateKeyPackage };
export type { KeyPackage };
