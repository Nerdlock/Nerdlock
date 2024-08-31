import { Encoder } from "../Encoding";
import type { CipherSuiteType, ExtensionType, ProtocolVersion } from "../Enums";
import type { Extension } from "../Extension";
import { EncodeLeafNode, IsLeafNodeKeyPackage, type LeafNodeKeyPackage } from "../RatchetTree";
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
    encoder.writeUint16(Uint16.from(keyPackage.version));
    encoder.writeUint16(Uint16.from(keyPackage.cipher_suite));
    encoder.writeUint8Array(keyPackage.init_key);
    encoder.writeUint8Array(EncodeLeafNode(keyPackage.leaf_node));
    return encoder.flush();
}

export type { KeyPackage };
export { IsKeyPackage, ConstructKeyPackageSignatureData };
