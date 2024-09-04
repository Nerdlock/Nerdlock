import ArrayTree, { type IndexedType } from "./ArrayTree";
import { DecodeCredential, EncodeCredential, IsCredential, type Credential } from "./Credential";
import { GenerateKeyPair, GetAllCipherSuites, GetCurrentTime, Hash, SignWithLabel } from "./CryptoHelper";
import { Decoder, Encoder } from "./Encoding";
import { CredentialType, ExtensionType, LeafNodeSource, ProtocolVersion, type CipherSuiteType, type ProposalType } from "./Enums";
import EncodeError from "./errors/EncodeError";
import InvalidObjectError from "./errors/InvalidObjectError";
import { DecodeExtension, EncodeExtension, IsExtension, type Extension } from "./Extension";
import Uint16 from "./types/Uint16";
import Uint32 from "./types/Uint32";
import Uint64 from "./types/Uint64";
import Uint8 from "./types/Uint8";

interface TreeNodeBase {
    encryption_key: Uint8Array;
}

interface ParentNode extends TreeNodeBase {
    parent_hash: Uint8Array;
    unmerged_leaves: Uint32Array;
}

function IsParentNode(object: unknown): object is ParentNode {
    return (
        typeof object === "object" &&
        object !== null &&
        "encryption_key" in object &&
        object.encryption_key instanceof Uint8Array &&
        "parent_hash" in object &&
        object.parent_hash instanceof Uint8Array &&
        "unmerged_leaves" in object &&
        object.unmerged_leaves instanceof Uint32Array
    );
}

function EncodeParentNode(node: ParentNode) {
    const encoder = new Encoder();
    encoder.writeUint8Array(node.encryption_key);
    encoder.writeUint8Array(node.parent_hash);
    encoder.writeArray([...node.unmerged_leaves], (l, encoder) => encoder.writeUint(Uint32.from(l)));
    return encoder.flush();
}

function DecodeParentNode(decoder: Decoder): ParentNode {
    const encryption_key = decoder.readUint8Array();
    const parent_hash = decoder.readUint8Array();
    const unmerged_leaves = new Uint32Array(decoder.readArray((decoder) => decoder.readUint32().value));
    return {
        encryption_key,
        parent_hash,
        unmerged_leaves
    } satisfies ParentNode;
}

export { DecodeParentNode, EncodeParentNode, IsParentNode };
export type { ParentNode };

interface Capabilities {
    versions: ProtocolVersion[];
    cipher_suites: CipherSuiteType[];
    extensions: ExtensionType[];
    proposals: ProposalType[];
    credentials: CredentialType[];
}

function IsCapabilities(object: unknown): object is Capabilities {
    return (
        typeof object === "object" &&
        object !== null &&
        "versions" in object &&
        object.versions instanceof Array &&
        object.versions.every((v) => typeof v === "number") &&
        "cipher_suites" in object &&
        object.cipher_suites instanceof Array &&
        object.cipher_suites.every((v) => typeof v === "number") &&
        "extensions" in object &&
        object.extensions instanceof Array &&
        object.extensions.every((v) => typeof v === "number") &&
        "proposals" in object &&
        object.proposals instanceof Array &&
        object.proposals.every((v) => typeof v === "number") &&
        "credentials" in object &&
        object.credentials instanceof Array &&
        object.credentials.every((v) => typeof v === "number") &&
        // only fields are versions, cipher_suites, extensions, proposals, credentials
        Object.keys(object).length === 5
    );
}

function EncodeCapabilities(capabilities: Capabilities) {
    const encoder = new Encoder();
    encoder.writeArray(capabilities.versions, (v, encoder) => encoder.writeUint(Uint16.from(v)));
    encoder.writeArray(capabilities.cipher_suites, (v, encoder) => encoder.writeUint(Uint16.from(v)));
    encoder.writeArray(capabilities.extensions, (v, encoder) => encoder.writeUint(Uint16.from(v)));
    encoder.writeArray(capabilities.proposals, (v, encoder) => encoder.writeUint(Uint16.from(v)));
    encoder.writeArray(capabilities.credentials, (v, encoder) => encoder.writeUint(Uint16.from(v)));
    return encoder.flush();
}

function DecodeCapabilities(decoder: Decoder): Capabilities {
    const versions = decoder.readArray<ProtocolVersion>((decoder) => decoder.readUint16().value);
    const cipher_suites = decoder.readArray<CipherSuiteType>((decoder) => decoder.readUint16().value);
    const extensions = decoder.readArray<ExtensionType>((decoder) => decoder.readUint16().value);
    const proposals = decoder.readArray<ProposalType>((decoder) => decoder.readUint16().value);
    const credentials = decoder.readArray<CredentialType>((decoder) => decoder.readUint16().value);
    const capabilities = {
        versions,
        cipher_suites,
        extensions,
        proposals,
        credentials
    } satisfies Capabilities;
    if (!IsCapabilities(capabilities)) {
        throw new InvalidObjectError("Invalid capabilities");
    }
    return capabilities;
}

function GetDefaultCapabilities(): Capabilities {
    return {
        versions: [ProtocolVersion.mls10],
        cipher_suites: GetAllCipherSuites(),
        extensions: [],
        credentials: [CredentialType.basic, CredentialType.x509],
        proposals: []
    } satisfies Capabilities;
}

export { DecodeCapabilities, EncodeCapabilities, GetDefaultCapabilities, IsCapabilities };
export type { Capabilities };

interface Lifetime {
    not_before: Uint64;
    not_after: Uint64;
}

function IsLifeTime(object: unknown): object is Lifetime {
    return (
        typeof object === "object" &&
        object !== null &&
        "not_before" in object &&
        object.not_before instanceof Uint64 &&
        "not_after" in object &&
        object.not_after instanceof Uint64
    );
}

function EncodeLifeTime(lifetime: Lifetime) {
    const encoder = new Encoder();
    encoder.writeUint(lifetime.not_before);
    encoder.writeUint(lifetime.not_after);
    return encoder.flush();
}

function DecodeLifetime(decoder: Decoder): Lifetime {
    const not_before = decoder.readUint64();
    const not_after = decoder.readUint64();
    const lifetime = {
        not_before,
        not_after
    };
    if (!IsLifeTime(lifetime)) {
        throw new InvalidObjectError("Invalid lifetime");
    }
    return lifetime;
}

interface LeafNodeBase {
    encryption_key: Uint8Array;
    signature_key: Uint8Array;
    credential: Credential;
    capabilities: Capabilities;
    leaf_node_source: LeafNodeSource;
    extensions: Extension<ExtensionType.application_id>[];
    signature?: Uint8Array;
}

interface LeafNodeKeyPackage extends LeafNodeBase {
    leaf_node_source: LeafNodeSource.key_package;
    lifetime: Lifetime;
}

interface LeafNodeCommit extends LeafNodeBase {
    leaf_node_source: LeafNodeSource.commit;
    parent_hash: Uint8Array;
}

type LeafNode = LeafNodeBase | LeafNodeKeyPackage | LeafNodeCommit;

function IsLeafNodeBase(object: unknown): object is LeafNodeBase {
    return (
        typeof object === "object" &&
        object !== null &&
        "encryption_key" in object &&
        object.encryption_key instanceof Uint8Array &&
        "signature_key" in object &&
        object.signature_key instanceof Uint8Array &&
        "credential" in object &&
        IsCredential(object.credential) &&
        "capabilities" in object &&
        IsCapabilities(object.capabilities) &&
        "leaf_node_source" in object &&
        typeof object.leaf_node_source === "number" &&
        "extensions" in object &&
        Array.isArray(object.extensions) &&
        object.extensions.every((e) => IsExtension(e, [ExtensionType.application_id])) &&
        // signature either doesn't exist or is a Uint8Array
        (("signature" in object && object.signature instanceof Uint8Array) || !("signature" in object))
    );
}

function IsLeafNodeKeyPackage(object: unknown): object is LeafNodeKeyPackage {
    if (!IsLeafNodeBase(object)) {
        return false;
    }
    // leaf_node_source is LeafNodeSource.key_package
    return object.leaf_node_source === LeafNodeSource.key_package && "lifetime" in object && IsLifeTime(object.lifetime);
}

function IsLeafNodeCommit(object: unknown): object is LeafNodeCommit {
    if (!IsLeafNodeBase(object)) {
        return false;
    }
    // leaf_node_source is LeafNodeSource.commit
    return object.leaf_node_source === LeafNodeSource.commit && "parent_hash" in object && object.parent_hash instanceof Uint8Array;
}

function IsLeafNode(object: unknown): object is LeafNode {
    return IsLeafNodeBase(object) || IsLeafNodeKeyPackage(object) || IsLeafNodeCommit(object);
}

function ConstructLeafNodeSignatureData(node: LeafNode, group_id?: Uint8Array, leaf_index?: Uint32) {
    // encode a LeafNodeTBS structure to be used for signing/verification
    const encoder = new Encoder();
    encoder.writeUint8Array(node.encryption_key);
    encoder.writeUint8Array(node.signature_key);
    encoder.writeUint8Array(EncodeCredential(node.credential), false);
    encoder.writeUint8Array(EncodeCapabilities(node.capabilities), false);
    encoder.writeUint(Uint8.from(node.leaf_node_source));
    if (IsLeafNodeKeyPackage(node)) {
        const lifetime = EncodeLifeTime(node.lifetime);
        encoder.writeUint8Array(lifetime, false);
    }
    if (IsLeafNodeCommit(node)) {
        encoder.writeUint8Array(node.parent_hash);
    }
    encoder.writeArray(node.extensions, (e, encoder) => encoder.writeUint8Array(EncodeExtension(e), false));
    if (node.leaf_node_source === LeafNodeSource.update || node.leaf_node_source === LeafNodeSource.commit) {
        if (group_id == null) {
            throw new EncodeError("Group id is missing");
        }
        if (leaf_index == null) {
            throw new EncodeError("Leaf index is missing");
        }
        encoder.writeUint8Array(group_id);
        encoder.writeUint(leaf_index);
    }
    return encoder.flush();
}

function EncodeLeafNode(node: LeafNode) {
    if (node.signature == null) {
        throw new Error("Signature is missing");
    }
    const encoder = new Encoder();
    encoder.writeUint8Array(node.encryption_key);
    encoder.writeUint8Array(node.signature_key);
    encoder.writeUint8Array(EncodeCredential(node.credential), false);
    encoder.writeUint8Array(EncodeCapabilities(node.capabilities), false);
    encoder.writeUint(Uint8.from(node.leaf_node_source));
    if (IsLeafNodeKeyPackage(node)) {
        const lifetime = EncodeLifeTime(node.lifetime);
        encoder.writeUint8Array(lifetime, false);
    }
    if (IsLeafNodeCommit(node)) {
        encoder.writeUint8Array(node.parent_hash);
    }
    encoder.writeArray(node.extensions, (e, encoder) => encoder.writeUint8Array(EncodeExtension(e), false));
    encoder.writeUint8Array(node.signature);
    return encoder.flush();
}

function DecodeLeafNode(decoder: Decoder): LeafNode {
    const encryption_key = decoder.readUint8Array();
    const signature_key = decoder.readUint8Array();
    const credential = DecodeCredential(decoder);
    const capabilities = DecodeCapabilities(decoder);
    const leaf_node_source = decoder.readUint8().value;
    let lifetime: Lifetime | undefined = undefined;
    let parent_hash: Uint8Array | undefined = undefined;
    if (leaf_node_source === LeafNodeSource.key_package) {
        lifetime = DecodeLifetime(decoder);
    }
    if (leaf_node_source === LeafNodeSource.commit) {
        parent_hash = decoder.readUint8Array();
    }
    const extensions = decoder.readArray((decoder) => DecodeExtension(decoder));
    const signature = decoder.readUint8Array();
    const leaf_node = {
        encryption_key,
        signature_key,
        credential,
        capabilities,
        leaf_node_source,
        lifetime,
        parent_hash,
        extensions,
        signature
    };
    if (!IsLeafNode(leaf_node)) {
        throw new InvalidObjectError("Invalid leaf node");
    }
    return leaf_node;
}

interface GenerateLeafNodeParams {
    cipherSuite: CipherSuiteType;
    signingKeyPriv: Uint8Array;
    signingKeyPub: Uint8Array;
    credential: Credential;
    extensions: Extension<ExtensionType.application_id>[];
    validFor?: bigint;
}

async function GenerateLeafNode(params: GenerateLeafNodeParams) {
    const { cipherSuite, signingKeyPriv, signingKeyPub, credential, extensions, validFor } = params;
    const leafKeyPair = await GenerateKeyPair(cipherSuite);
    // create the leaf node
    const currTime = GetCurrentTime();
    const leafNode = {
        encryption_key: leafKeyPair.publicKey,
        capabilities: GetDefaultCapabilities(),
        signature_key: signingKeyPub,
        credential,
        extensions,
        leaf_node_source: LeafNodeSource.key_package,
        lifetime: {
            not_before: Uint64.from(currTime),
            not_after: Uint64.from(currTime + (validFor ?? 86400n))
        },
        signature: new Uint8Array(0)
    } satisfies LeafNodeKeyPackage;
    const leafNodeSignatureData = ConstructLeafNodeSignatureData(leafNode);
    const leafNodeSignature = await SignWithLabel(
        signingKeyPriv,
        new TextEncoder().encode("LeafNodeTBS"),
        leafNodeSignatureData,
        cipherSuite
    );
    leafNode.signature = leafNodeSignature;
    return { node: leafNode, nodePrivateKey: leafKeyPair.privateKey };
}

export {
    ConstructLeafNodeSignatureData,
    DecodeLeafNode,
    EncodeLeafNode,
    GenerateLeafNode,
    IsLeafNode,
    IsLeafNodeBase,
    IsLeafNodeCommit,
    IsLeafNodeKeyPackage
};
export type { LeafNode, LeafNodeCommit, LeafNodeKeyPackage };

type RatchetTreeNode = ParentNode | LeafNode;

export default class RatchetTree extends ArrayTree<RatchetTreeNode> {
    async hash(node: IndexedType<RatchetTreeNode>, cipherSuite: CipherSuiteType) {
        // check if node is a leaf
        if (node.index % 2 === 0) {
            const encoder = new Encoder();
            encoder.writeUint(Uint32.from(node.index));
            if (node.data != null) {
                const leafData = node.data as LeafNode;
                encoder.writeUint8Array(EncodeLeafNode(leafData), false);
            }
            return Hash(encoder.flush(), cipherSuite);
        }
        // recursively hash the parent's children
        const encoder = new Encoder();
        if (node.data != null) {
            const parentData = node.data as ParentNode;
            encoder.writeUint8Array(EncodeParentNode(parentData), false);
        }
        encoder.writeUint8Array(await this.hash(node.left(), cipherSuite));
        encoder.writeUint8Array(await this.hash(node.right(), cipherSuite));
        return Hash(encoder.flush(), cipherSuite);
    }

    addLeaf(leaf: LeafNode) {
        let firstEmpty = this.firstEmptyLeaf;
        if (firstEmpty == null) {
            this.extend();
        }
        firstEmpty = this.firstEmptyLeaf;
        if (!IsLeafNode(firstEmpty?.data)) {
            throw new Error("No empty leaves after extending???");
        }
        firstEmpty.data = leaf;
    }

    resolution(node: IndexedType<RatchetTreeNode>) {
        /*
        The resolution of a node is an ordered list of non-blank nodes that collectively cover all non-blank descendants of the node. The resolution of the root contains the set of keys that are collectively necessary to encrypt to every node in the group. The resolution of a node is effectively a depth-first, left-first enumeration of the nearest non-blank nodes below the node:

The resolution of a non-blank node comprises the node itself, followed by its list of unmerged leaves, if any.
The resolution of a blank leaf node is the empty list.
The resolution of a blank intermediate node is the result of concatenating the resolution of its left child with the resolution of its right child, in that order.
        */
    }

    static buildFromLeaves(leaves: LeafNode[]) {
        const width = ArrayTree.width(leaves.length);
        const tree = new RatchetTree(leaves.length);
        for (let i = 0; i < width; i++) {
            if (i % 2 === 0) {
                const leaf = leaves[i >> 1];
                tree.setNode(i, leaf);
            } else {
                tree.setNode(i, undefined);
            }
        }
        return tree;
    }

    static buildFromNodes(nodes: RatchetTreeNode[]) {
        const tree = new RatchetTree(ArrayTree.reverseWidth(nodes.length));
        for (let i = 0; i < nodes.length; i++) {
            tree.setNode(i, nodes[i]);
        }
        return tree;
    }
}
