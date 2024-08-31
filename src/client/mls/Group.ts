import type { Credential } from "./Credential";
import { ArraysEqual, DecodeCipherSuiteType, GenerateKeyPair, GenerateSigningKeyPair, GetCurrentTime, SignWithLabel, VerifyWithLabel } from "./CryptoHelper";
import { CipherSuiteType, CredentialType, ExtensionType, LeafNodeSource, ProtocolVersion } from "./Enums";
import InvalidObjectError from "./errors/InvalidObjectError";
import type { Extension } from "./Extension";
import { EncodeGroupContext, type GroupContext } from "./GroupContext";
import { ConstructKeyPackageSignatureData, type KeyPackage } from "./messages/KeyPackage";
import RatchetTree from "./RatchetTree";
import { ConstructLeafNodeSignatureData, GetDefaultCapabilities, type LeafNode } from "./RatchetTree";
import type Uint32 from "./types/Uint32";
import Uint64 from "./types/Uint64";

class Group {
    #ratchetTree: RatchetTree;
    #groupContext: GroupContext;

    constructor(ratchetTree: RatchetTree, groupContext: GroupContext) {
        this.#ratchetTree = ratchetTree;
        this.#groupContext = groupContext;
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

    async validateLeafNode(node: LeafNode, source: LeafNodeSource, leaf_index?: Uint32) {
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
        // verify lifetime
        // verify that the leaf node's extensions are in the capabilities.extensions
        if (!node.extensions.every((e) => node.capabilities.extensions.includes(e.extension_type))) {
            throw new InvalidObjectError("Extension type not found in capabilities");
        }
        // verify the leaf_node_source matches the source
        if (node.leaf_node_source !== source) {
            throw new InvalidObjectError("Leaf node source does not match the source");
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
        console.log(EncodeGroupContext(groupContext), groupContext);
        return {
            group: new Group(ratchetTree, groupContext),
            encryptionKeyPair
        }
    }
}

const cipherSuite = CipherSuiteType.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const signingKeyPair = await GenerateSigningKeyPair(cipherSuite);
const credential = {
    credential_type: CredentialType.basic,
    identity: new TextEncoder().encode("test"),
} satisfies Credential;
const {group, encryptionKeyPair} = await Group.create(signingKeyPair.publicKey, signingKeyPair.privateKey, credential, [], [], cipherSuite);
console.log(group, encryptionKeyPair);