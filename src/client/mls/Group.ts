import type { Credential } from "./Credential";
import { ArraysEqual, DecodeCipherSuiteType, GenerateKeyPair, GenerateSigningKeyPair, GetCurrentTime, MAC, SignWithLabel, VerifyWithLabel } from "./CryptoHelper";
import { CipherSuiteType, CredentialType, ExtensionType, LeafNodeSource, ProtocolVersion } from "./Enums";
import InvalidObjectError from "./errors/InvalidObjectError";
import type { Extension } from "./Extension";
import { type GroupContext } from "./GroupContext";
import KeySchedule from "./KeySchedule";
import { ConstructKeyPackageSignatureData, type KeyPackage } from "./messages/KeyPackage";
import type { AddProposal } from "./proposals/Add";
import type { UpdateProposal } from "./proposals/Update";
import RatchetTree, { ConstructLeafNodeSignatureData, GetDefaultCapabilities, type LeafNode } from "./RatchetTree";
import type Uint32 from "./types/Uint32";
import Uint64 from "./types/Uint64";

class Group {
    #ratchetTree: RatchetTree;
    #groupContext: GroupContext;
    #keySchedule: KeySchedule;

    constructor(ratchetTree: RatchetTree, groupContext: GroupContext, keySchedule: KeySchedule) {
        this.#ratchetTree = ratchetTree;
        this.#groupContext = groupContext;
        this.#keySchedule = keySchedule;
    }

    async validateKeyPackage(keyPackage: KeyPackage) {
        // validate cipher suite and protocol version
        if (keyPackage.version !== this.#groupContext.version) {
            throw new InvalidObjectError("Key package version does not match group context version");
        }
        if (keyPackage.cipher_suite !== this.#groupContext.cipher_suite) {
            throw new InvalidObjectError("Key package cipher suite does not match group context cipher suite");
        }
        // verify leaf node
        const validLeafNode = await this.validateLeafNode(keyPackage.leaf_node, LeafNodeSource.key_package).catch(() => false);
        if (validLeafNode === false) {
            throw new InvalidObjectError("Leaf node is invalid");
        }
        // verify signature
        const signatureContent = ConstructKeyPackageSignatureData(keyPackage);
        const signature = keyPackage.signature;
        if (signature == null) {
            throw new InvalidObjectError("Signature is missing");
        }
        const signatureKey = keyPackage.leaf_node.signature_key;
        if (!(await VerifyWithLabel(signatureKey, new TextEncoder().encode("KeyPackageTBS"), signatureContent, signature, keyPackage.cipher_suite))) {
            throw new InvalidObjectError("Invalid signature");
        }
        // verify that the leaf node's encryption key is different from init key
        if (ArraysEqual(keyPackage.init_key, keyPackage.leaf_node.encryption_key)) {
            throw new InvalidObjectError("Init key is the same as the leaf node's encryption key");
        }
        return true;
    }

    async validateLeafNode(node: LeafNode, source: LeafNodeSource, leaf_index?: Uint32, prev_leaf_node?: LeafNode) {
        const groupContext = this.#groupContext;
        const groupLeaves = this.#ratchetTree.leaves;
        const cipherSuite = groupContext.cipher_suite;
        // validate credential
        // validate signature
        const signatureContent = ConstructLeafNodeSignatureData(node, leaf_index != null ? groupContext.group_id : undefined, leaf_index ?? undefined);
        const signature = node.signature;
        if (signature == null) {
            throw new InvalidObjectError("Signature is missing");
        }
        const signatureKey = node.signature_key;
        if (!(await VerifyWithLabel(signatureKey, new TextEncoder().encode("LeafNodeTBS"), signatureContent, signature, cipherSuite))) {
            throw new InvalidObjectError("Invalid signature");
        }
        // validate compatibility with group context
        const requiredCapabilities = groupContext.extensions.find((e) => e.extension_type === ExtensionType.required_capabilities) as Extension<ExtensionType.required_capabilities>;
        if (requiredCapabilities != null) {
            // verify that every extensions, proposals and credentials types are found in the capabilities
            if (!requiredCapabilities.extension_data.credential_types.every((c) => node.capabilities.credentials.includes(c))) {
                throw new InvalidObjectError("Credential type not found in capabilities");
            }
            if (!requiredCapabilities.extension_data.proposal_types.every((p) => node.capabilities.proposals.includes(p))) {
                throw new InvalidObjectError("Proposal type not found in capabilities");
            }
            if (!requiredCapabilities.extension_data.extension_types.every((e) => node.capabilities.extensions.includes(e))) {
                throw new InvalidObjectError("Extension type not found in capabilities");
            }
        }
        // verify that the leaf node's credential is supported by every leaf node in the group
        for (const leaf of groupLeaves.map(l => l.data as LeafNode)) {
            if (!leaf.capabilities.credentials.includes(node.credential.credential_type)) {
                throw new InvalidObjectError("Credential type not supported by a group member");
            }
        }
        // according to MLS protocol, it is only recommended to verify the lifetime of the leaf node, so screw it, we ain't doing it L
        // verify that the leaf node's extensions are in the capabilities.extensions
        if (!node.extensions.every((e) => node.capabilities.extensions.includes(e.extension_type))) {
            throw new InvalidObjectError("Extension type not found in capabilities");
        }
        // verify the leaf_node_source matches the source
        if (node.leaf_node_source !== source) {
            throw new InvalidObjectError("Leaf node source does not match the source");
        }
        // if this is coming from an update proposal, verify that thew new encryption_key iis different than the previous one
        if (source === LeafNodeSource.update) {
            if (prev_leaf_node == null) {
                throw new Error("Previous leaf node is missing");
            }
            if (ArraysEqual(prev_leaf_node.encryption_key, node.encryption_key)) {
                throw new InvalidObjectError("Encryption key is the same as the previous one");
            }
        }
        // verify that signature_key and encryption_key is unique amongst the group
        const uniqueKeys = new Array<Uint8Array>();
        for (const leaf of groupLeaves.map(l => l.data as LeafNode)) {
            uniqueKeys.push(leaf.signature_key);
            uniqueKeys.push(leaf.encryption_key);
        }
        if (!uniqueKeys.every(k => !ArraysEqual(k, node.signature_key) && !ArraysEqual(k, node.encryption_key))) {
            throw new InvalidObjectError("Signature key or encryption key is not unique");
        }
        return true;
    }

    async processAddProposal(proposal: AddProposal) {
        // the proposal is only valid, if the key_package is valid
        const keyPackageValid = await this.validateKeyPackage(proposal.key_package).catch(() => false);
        if (!keyPackageValid) {
            throw new InvalidObjectError("Key package is not valid");
        }
        // add the new leaf node to the tree
        this.#ratchetTree.addLeaf(proposal.key_package.leaf_node);
    }

    async processUpdateProposal(proposal: UpdateProposal, prevLeafNode: LeafNode, leaf_index: Uint32) {
        // the proposal is only valid, if the leaf_node is valid
        const leafNodeValid = await this.validateLeafNode(proposal.leaf_node, LeafNodeSource.update, leaf_index, prevLeafNode).catch(() => false);
        if (!leafNodeValid) {
            throw new InvalidObjectError("Leaf node is not valid");
        }
        // update the leaf node in the tree
        this.#ratchetTree.setNode(leaf_index.value, proposal.leaf_node);
        // go through every intermediate node and blank it
        const nodes = this.#ratchetTree.directPath(this.#ratchetTree.getIndexedNode(leaf_index.value));
        // pop the last node (the node)
        nodes.pop();
        for (const node of nodes) {
            this.#ratchetTree.setNode(node.index, undefined);
        }
    }

    /**
     * Create a new group with the given parameters.
     * After the group is created, the DS will be contacted and the function will fail if the DS rejects the group.
     */
    static async create(signatureKeyPub: Uint8Array, signatureKeyPriv: Uint8Array, credential: Credential, clientExtensions: Extension<ExtensionType.application_id>[], groupExtensions: Extension<ExtensionType.required_capabilities>[], cipherSuite: CipherSuiteType) {
        const suite = DecodeCipherSuiteType(cipherSuite);
        // generate a new encryption keypair
        const encryptionKeyPair = await GenerateKeyPair(cipherSuite);
        const currentTime = Uint64.from(GetCurrentTime());
        // construct our leaf node
        const leafNode = {
            encryption_key: encryptionKeyPair.publicKey,
            signature_key: signatureKeyPub,
            credential,
            capabilities: GetDefaultCapabilities(),
            leaf_node_source: LeafNodeSource.key_package,
            lifetime: {
                not_before: currentTime.subtract(Uint64.from(86400n)),
                not_after: currentTime.add(Uint64.from(86400n))
            },
            extensions: clientExtensions,
            signature: new Uint8Array(0)
        } satisfies LeafNode;
        const signatureData = ConstructLeafNodeSignatureData(leafNode);
        const signature = await SignWithLabel(signatureKeyPriv, new TextEncoder().encode("LeafNodeTBS"), signatureData, cipherSuite);
        leafNode.signature = signature;
        // construct the ratchet tree
        const ratchetTree = RatchetTree.buildFromLeaves([leafNode]);
        // construct the group context
        const groupId = crypto.getRandomValues(new Uint8Array(suite.kdf.hashSize));
        const groupContext = {
            version: ProtocolVersion.mls10,
            cipher_suite: cipherSuite,
            group_id: groupId,
            epoch: Uint64.from(0n),
            confirmed_transcript_hash: new Uint8Array(0),
            extensions: groupExtensions,
            tree_hash: await ratchetTree.hash(ratchetTree.root, cipherSuite)
        } satisfies GroupContext;
        // construct the key schedule
        const epochSecret = crypto.getRandomValues(new Uint8Array(suite.kdf.hashSize));
        const keySchedule = await KeySchedule.fromEpochSecret(epochSecret, cipherSuite);
        const group = new Group(ratchetTree, groupContext, keySchedule);
        // construct the confirmation_tag
        const confirmation_key = keySchedule.getSecret("confirmation_key");
        if (confirmation_key == null) {
            throw new Error("Confirmation key not set");
        }
        const confirmation_tag = await MAC(confirmation_key, group.#groupContext.confirmed_transcript_hash, cipherSuite);
        // compute the interim transcript hash
        await keySchedule.computeInterimTranscriptHash(group.#groupContext.confirmed_transcript_hash, confirmation_tag);
        // the group is ready, ask the DS to validate the group
        // TODO: implement the DS
        return {
            group,
            encryptionKeyPair
        }
    }

    /**
     * Serialize the group as a raw Uint8Array. Used for storing on the client for later deserialization.
     * WARNING: This method will return data that could potentially be used to compromise the security of the group. DO NOT SEND OUTSIDE THE CLIENT AT ALL TIMES.
     * @returns The serialized group.
     */
    serialize() {
        throw new Error("Not implemented");
    }

    /**
     * Construct a group from a serialized Uint8Array. Used for deserializing a group from storage.
     * @param data The serialized group.
     * @returns The deserialized group.
     */
    static deserialize(data: Uint8Array) {
        throw new Error("Not implemented");
    }
}

const cipherSuite = CipherSuiteType.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const signingKeyPair = await GenerateSigningKeyPair(cipherSuite);
const credential = {
    credential_type: CredentialType.basic,
    identity: new TextEncoder().encode("test"),
} satisfies Credential;
const { group, encryptionKeyPair } = await Group.create(signingKeyPair.publicKey, signingKeyPair.privateKey, credential, [], [], cipherSuite);
console.log(group, encryptionKeyPair);