import ArrayTree, { type IndexedType } from "./ArrayTree";
import { DecodeCredential, EncodeCredential, IsCredential, type Credential } from "./Credential";
import { GetAllCipherSuites, Hash } from "./CryptoHelper";
import { Decoder, Encoder } from "./Encoding";
import { CredentialType, ExtensionType, LeafNodeSource, ProtocolVersion, type CipherSuiteType, type ProposalType } from "./Enums";
import EncodeError from "./errors/EncodeError";
import InvalidObjectError from "./errors/InvalidObjectError";
import { DecodeExtension, EncodeExtension, type Extension } from "./Extension";
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
    encoder.writeUint(Uint32.from(node.unmerged_leaves.length));
    node.unmerged_leaves.forEach((l) => encoder.writeUint(Uint32.from(l)));
    return encoder.flush();
}

function DecodeParentNode(decoder: Decoder): ParentNode {
    const encryption_key = decoder.readUint8Array();
    const parent_hash = decoder.readUint8Array();
    const unmerged_leaves = new Uint32Array(decoder.readUint32().value);
    for (let i = 0; i < unmerged_leaves.length; i++) {
        unmerged_leaves[i] = decoder.readUint32().value;
    }
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
    encoder.writeUint(Uint16.from(capabilities.versions.length));
    capabilities.versions.forEach((v) => encoder.writeUint(Uint16.from(v)));
    encoder.writeUint(Uint16.from(capabilities.cipher_suites.length));
    capabilities.cipher_suites.forEach((v) => encoder.writeUint(Uint16.from(v)));
    encoder.writeUint(Uint16.from(capabilities.extensions.length));
    capabilities.extensions.forEach((v) => encoder.writeUint(Uint16.from(v)));
    encoder.writeUint(Uint16.from(capabilities.proposals.length));
    capabilities.proposals.forEach((v) => encoder.writeUint(Uint16.from(v)));
    encoder.writeUint(Uint16.from(capabilities.credentials.length));
    capabilities.credentials.forEach((v) => encoder.writeUint(Uint16.from(v)));
    return encoder.flush();
}

function DecodeCapabilities(decoder: Decoder): Capabilities {
    const versions: ProtocolVersion[] = [];
    const cipher_suites: CipherSuiteType[] = [];
    const extensions: ExtensionType[] = [];
    const proposals: ProposalType[] = [];
    const credentials: CredentialType[] = [];
    const versionsLength = decoder.readUint16().value;
    for (let i = 0; i < versionsLength; i++) {
        const version = decoder.readUint16().value;
        versions.push(version);
    }
    const cipher_suitesLength = decoder.readUint16().value;
    for (let i = 0; i < cipher_suitesLength; i++) {
        const cipher_suite = decoder.readUint16().value;
        cipher_suites.push(cipher_suite);
    }
    const extensionsLength = decoder.readUint16().value;
    for (let i = 0; i < extensionsLength; i++) {
        const extension = decoder.readUint16().value;
        extensions.push(extension);
    }
    const proposalsLength = decoder.readUint16().value;
    for (let i = 0; i < proposalsLength; i++) {
        const proposal = decoder.readUint16().value;
        proposals.push(proposal);
    }
    const credentialsLength = decoder.readUint16().value;
    for (let i = 0; i < credentialsLength; i++) {
        const credential = decoder.readUint16().value;
        credentials.push(credential);
    }
    return {
        versions,
        cipher_suites,
        extensions,
        proposals,
        credentials
    } satisfies Capabilities;
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
    }
    if(!IsLifeTime(lifetime)) {
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
        [
            LeafNodeSource.key_package,
            LeafNodeSource.update,
            LeafNodeSource.commit
        ].includes(object.leaf_node_source) &&
        "extensions" in object &&
        object.extensions === undefined &&
        (// signature either doesn't exist or is a Uint8Array
            ("signature" in object && object.signature instanceof Uint8Array) ||
            !("signature" in object)
        )
    );
}

function IsLeafNodeKeyPackage(object: unknown): object is LeafNodeKeyPackage {
    if (!IsLeafNodeBase(object)) {
        return false;
    }
    // leaf_node_source is LeafNodeSource.key_package
    return (
        object.leaf_node_source === LeafNodeSource.key_package &&
        "lifetime" in object &&
        IsLifeTime(object.lifetime)
    );
}

function IsLeafNodeCommit(object: unknown): object is LeafNodeCommit {
    if (!IsLeafNodeBase(object)) {
        return false;
    }
    // leaf_node_source is LeafNodeSource.commit
    return (
        object.leaf_node_source === LeafNodeSource.commit &&
        "parent_hash" in object &&
        object.parent_hash instanceof Uint8Array
    );
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
        encoder.writeUint(node.lifetime.not_before);
        encoder.writeUint(node.lifetime.not_after);
    }
    if (IsLeafNodeCommit(node)) {
        encoder.writeUint8Array(node.parent_hash);
    }
    encoder.writeUint(Uint16.from(node.extensions.length));
    node.extensions.forEach((e) => encoder.writeUint8Array(EncodeExtension(e), false));
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
        encoder.writeUint8Array(EncodeLifeTime(node.lifetime), false);
    }
    if (IsLeafNodeCommit(node)) {
        encoder.writeUint8Array(node.parent_hash);
    }
    encoder.writeUint(Uint16.from(node.extensions.length));
    node.extensions.forEach((e) => encoder.writeUint8Array(EncodeExtension(e), false));
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
    if(leaf_node_source === LeafNodeSource.key_package) {
        lifetime = DecodeLifetime(decoder);
    }
    if(leaf_node_source === LeafNodeSource.commit) {
        parent_hash = decoder.readUint8Array();
    }
    const extensionsLength = decoder.readUint16().value;
    const extensions: Extension<ExtensionType>[] = [];
    for (let i = 0; i < extensionsLength; i++) {
        extensions.push(DecodeExtension(decoder));
    }
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
    }
    if(!IsLeafNode(leaf_node)) {
        throw new InvalidObjectError("Invalid leaf node");
    }
    return leaf_node;
}

export { ConstructLeafNodeSignatureData, EncodeLeafNode, IsLeafNodeBase, IsLeafNodeCommit, IsLeafNodeKeyPackage, IsLeafNode, DecodeLeafNode };
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
        if(!IsLeafNode(firstEmpty?.data)) {
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
        const tree = new RatchetTree();
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
        const tree = new RatchetTree();
        for (let i = 0; i < nodes.length; i++) {
            tree.setNode(i, nodes[i]);
        }
        return tree;
    }
}