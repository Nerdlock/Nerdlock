import ArrayTree, { type IndexedType } from "./ArrayTree";
import type { UpdatePath, UpdatePathNode } from "./Commit";
import { DecodeCredential, EncodeCredential, IsCredential, type Credential } from "./Credential";
import { DecodeCipherSuiteType, DeriveKeyPair, DeriveSecret, EncryptWithLabel, GenerateKeyPair, GetAllCipherSuites, GetCurrentTime, Hash, SignWithLabel } from "./CryptoHelper";
import { Decoder, Encoder } from "./Encoding";
import { CredentialType, ExtensionType, LeafNodeSource, ProtocolVersion, type CipherSuiteType, type ProposalType } from "./Enums";
import EncodeError from "./errors/EncodeError";
import InvalidObjectError from "./errors/InvalidObjectError";
import { DecodeExtension, EncodeExtension, IsExtension, type Extension } from "./Extension";
import { EncodeGroupContext, type GroupContext } from "./GroupContext";
import Uint16 from "./types/Uint16";
import Uint32 from "./types/Uint32";
import Uint64 from "./types/Uint64";
import Uint8 from "./types/Uint8";

interface TreeNodeBase {
    encryption_key: Uint8Array;
    private_key?: Uint8Array;
}

interface ParentNode extends TreeNodeBase {
    parent_hash: Uint8Array;
    unmerged_leaves: Array<number>;
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
        Array.isArray(object.unmerged_leaves) &&
        object.unmerged_leaves.every((l) => typeof l === "number")
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
    const unmerged_leaves = decoder.readArray((decoder) => decoder.readUint32().value);
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

interface LeafNodeBase extends TreeNodeBase {
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
        return firstEmpty;
    }

    resolution(node: IndexedType<RatchetTreeNode>): IndexedType<RatchetTreeNode>[] {
        /*
        The resolution of a node is an ordered list of non-blank nodes that collectively cover all non-blank descendants of the node. The resolution of the root contains the set of keys that are collectively necessary to encrypt to every node in the group. The resolution of a node is effectively a depth-first, left-first enumeration of the nearest non-blank nodes below the node:

    The resolution of a non-blank node comprises the node itself, followed by its list of unmerged leaves, if any.
    The resolution of a blank leaf node is the empty list.
    The resolution of a blank intermediate node is the result of concatenating the resolution of its left child with the resolution of its right child, in that order.
        */
        if (node.data != null) {
            if (IsParentNode(node.data)) {
                return [node, ...[...node.data.unmerged_leaves].map(l => this.getIndexedNode(l))];
            } else {
                return [node];
            }
        }
        if (node.index % 2 === 0) {
            return [];
        }
        return [...this.resolution(this.left(node)), ...this.resolution(this.right(node))];
    }

    filteredDirectPath(node: IndexedType<RatchetTreeNode>) {
        /*
        The filtered direct path of a leaf node L is the node's direct path, with any node removed whose child on the copath of L has an empty resolution (keeping in mind that any unmerged leaves of the copath child count toward its resolution). The removed nodes do not need their own key pairs because encrypting to the node's key pair would be equivalent to encrypting to its non-copath child.
        */
        const copathWithEmptyResolution = node.copath().filter(n => this.resolution(n).length === 0);
        return copathWithEmptyResolution.map(n => n.parent());
    }

    /**
     * Compute and set the parent hashes for a given node
     * @param node The starting node
     * @param cipherSuite The ciphersuite to use
     */
    async computeParentHashes(node: IndexedType<RatchetTreeNode>, cipherSuite: CipherSuiteType) {
        const copath = node.copath();
        const parentHashNodes = this.filteredDirectPath(node).toReversed();
        for (let i = 0; i < parentHashNodes.length; i++) {
            const parentHashNode = parentHashNodes[i];
            // get the copath child
            const copathChild = copath.find(c => c.parent().index === parentHashNode.index);
            if (copathChild == null) {
                throw new Error("Copath child not found (but should exist)");
            }
            const parentHashNodeData = this.assertParentNode(parentHashNode);
            // create the input for the parent hash
            const encoder = new Encoder();
            encoder.writeUint8Array(parentHashNodeData.encryption_key);
            // don't encode the parent hash if this is the root node
            if (i !== 0) {
                // get the parent hash of the above node in this filtered direct path (which is one index below)
                const nextNode = this.getIndexedNode(parentHashNodes[i - 1].index);
                const nextNodeData = this.assertParentNode(nextNode);
                encoder.writeUint8Array(nextNodeData.parent_hash);
            }
            // remove the unmerged leaves before hashing the copatch child
            for (const leaf of parentHashNodeData.unmerged_leaves) {
                const leafNode = this.getIndexedNode(leaf * 2);
                const leafNodePath = leafNode.directPath();
                for (const n of leafNodePath) {
                    if (n.data == null) {
                        continue;
                    }
                    const nodeData = this.assertParentNode(n);
                    nodeData.unmerged_leaves = nodeData.unmerged_leaves.filter(l => l !== leaf);
                    this.setNode(n.index, nodeData);
                }
            }
            encoder.writeUint8Array(await this.hash(copathChild, cipherSuite));
            const parentHashInput = encoder.flush();
            const parentHash = await Hash(parentHashInput, cipherSuite);
            parentHashNodeData.parent_hash = parentHash;
            this.setNode(parentHashNode.index, parentHashNodeData);
        };
    }

    /**
     * Update the direct path of a given note, and return the UpdatePath object
     */
    async updateDirectPath(leafNode: IndexedType<RatchetTreeNode>, groupContext: GroupContext, signature_key: Uint8Array, cipherSuite: CipherSuiteType) {
        // step 1: blank all nodes in the direct path of the node
        const directPath = leafNode.directPath();
        for (const n of directPath) {
            this.setNode(n.index, undefined);
        }
        // step 2: generate a new hpke key pair for the node
        const leafKeyPair = await GenerateKeyPair(cipherSuite);
        // generate the path secrets
        const suite = DecodeCipherSuiteType(cipherSuite);
        const pathSecrets = new Array<Uint8Array>();
        const initialPathSecret = crypto.getRandomValues(new Uint8Array(suite.kdf.hashSize));
        for (const [i, node] of this.filteredDirectPath(leafNode).entries()) {
            pathSecrets[i] = await DeriveSecret(i === 0 ? initialPathSecret : pathSecrets[i - 1], new TextEncoder().encode("path"), cipherSuite);
            // derive the node key pair using the secret
            const nodeSecret = await DeriveSecret(pathSecrets[i], new TextEncoder().encode("node"), cipherSuite);
            const nodeKeyPair = await DeriveKeyPair(nodeSecret, cipherSuite);
            const nodeData = this.assertParentNode(node);
            nodeData.private_key = nodeKeyPair.privateKey;
            nodeData.encryption_key = nodeKeyPair.publicKey;
            this.setNode(node.index, nodeData);
        }
        // time to generate parent hashes along the filtered direct path
        await this.computeParentHashes(leafNode, cipherSuite);
        // update this leaf node
        let leafData = this.assertLeafNode(leafNode);
        leafData = {
            ...leafData,
            private_key: leafKeyPair.privateKey,
            encryption_key: leafKeyPair.publicKey,
            leaf_node_source: LeafNodeSource.commit,
            parent_hash: this.assertParentNode(leafNode.parent()).parent_hash
        } satisfies LeafNodeCommit;
        const leafNodeSignatureData = ConstructLeafNodeSignatureData(leafData, groupContext.group_id, Uint32.from(leafNode.index / 2));
        leafData.signature = await SignWithLabel(
            signature_key,
            new TextEncoder().encode("LeafNodeTBS"),
            leafNodeSignatureData,
            cipherSuite
        );
        this.setNode(leafNode.index, leafData);
        return pathSecrets;
    }

    async encryptPathSecrets(leafNode: IndexedType<RatchetTreeNode>, pathSecrets: Array<Uint8Array>, groupContext: GroupContext, cipherSuite: CipherSuiteType) {
        const encryptedPaths = new Array<UpdatePathNode>();
        const encodedGroupContext = EncodeGroupContext(groupContext);
        const copath = leafNode.copath();
        for (const [i, parent] of this.filteredDirectPath(leafNode).entries()) {
            const copathChild = copath.find(c => c.parent().index === parent.index);
            if (copathChild == null) {
                throw new Error("Copath child not found (but should exist)");
            }
            const copathResolution = this.resolution(copathChild);
            for (const copathNode of copathResolution) {
                const copathData = this.assertParentNode(copathNode);
                const { ciphertext, encKey } = await EncryptWithLabel(copathData.encryption_key, new TextEncoder().encode("UpdatePathNode"), encodedGroupContext, pathSecrets[i + 1], cipherSuite);
                const updateNode = {
                    encryption_key: copathData.encryption_key,
                    encrypted_path_secret: {
                        kem_output: encKey,
                        ciphertext
                    }
                } satisfies UpdatePathNode;
                encryptedPaths.push(updateNode);
            }
        }
        return {
            leaf_node: this.assertLeafNode(leafNode),
            nodes: encryptedPaths
        } satisfies UpdatePath
    }

    clone() {
        return RatchetTree.buildFromNodes(this.nodes);
    }

    assertLeafNode(node?: IndexedType<RatchetTreeNode>) {
        if (node == null) {
            throw new Error("Node is null");
        }
        if (node.data == null) {
            throw new Error("Node is not a leaf (blank)");
        }
        if (!IsLeafNode(node.data)) {
            throw new Error("Node is not a leaf (different type)");
        }
        return node.data;
    }

    assertParentNode(node?: IndexedType<RatchetTreeNode>) {
        if (node == null) {
            throw new Error("Node is null");
        }
        if (node.data == null) {
            throw new Error("Node is not a parent (blank)");
        }
        if (!IsParentNode(node.data)) {
            throw new Error("Node is not a parent (different type)");
        }
        return node.data;
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

    static buildFromNodes(nodes: Array<RatchetTreeNode | undefined>) {
        const tree = new RatchetTree(ArrayTree.reverseWidth(nodes.length));
        for (let i = 0; i < nodes.length; i++) {
            tree.setNode(i, nodes[i]);
        }
        return tree;
    }
}
