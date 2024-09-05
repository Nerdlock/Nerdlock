import { bytesToHex } from "@noble/hashes/utils";
import type { Commit, ProposalOrRefProposal, UpdatePath } from "./Commit";
import type { Credential } from "./Credential";
import { ArraysEqual, DecodeCipherSuiteType, DeriveSecret, GenerateSigningKeyPair, MAC, VerifyWithLabel } from "./CryptoHelper";
import { CipherSuiteType, CredentialType, ExtensionType, LeafNodeSource, ProposalOrRefType, ProtocolVersion, SenderType, WireFormat } from "./Enums";
import InvalidObjectError from "./errors/InvalidObjectError";
import type { Extension } from "./Extension";
import { type GroupContext } from "./GroupContext";
import KeySchedule from "./KeySchedule";
import { ConstructFramedContentCommit, EncodeMLSMessage } from "./Message";
import { ConstructKeyPackageSignatureData, type KeyPackage } from "./messages/KeyPackage";
import { EncryptPrivateMessage } from "./messages/PrivateMessage";
import type { Proposal } from "./Proposal";
import { IsAddProposal, type AddProposal } from "./proposals/Add";
import { IsRemoveProposal, type RemoveProposal } from "./proposals/Remove";
import { IsUpdateProposal, type UpdateProposal } from "./proposals/Update";
import RatchetTree, { ConstructLeafNodeSignatureData, GenerateLeafNode, type LeafNode } from "./RatchetTree";
import Uint32 from "./types/Uint32";
import Uint64 from "./types/Uint64";

type ProposalFrom = Proposal & { proposal_from: Uint32 };

class Group {
    #ratchetTree: RatchetTree;
    #groupContext: GroupContext;
    #keySchedule: KeySchedule;
    #leafIndex: Uint32 = Uint32.from(0);
    #cachedProposals = new Array<ProposalFrom>();

    constructor(ratchetTree: RatchetTree, groupContext: GroupContext, keySchedule: KeySchedule) {
        this.#ratchetTree = ratchetTree;
        this.#groupContext = groupContext;
        this.#keySchedule = keySchedule;
    }

    async sendMessage(message: Uint8Array | Proposal | Commit, signature_key: Uint8Array) {
        const type = message instanceof Uint8Array ? "application" : "handshake";
        const { key, nonce, generation } = await this.#keySchedule.getMessageSecret(this.#leafIndex, type);
        const sender_data_secret = this.#keySchedule.getSecret("sender_data_secret");
        if (sender_data_secret == null) {
            throw new Error("Sender data secret not set");
        }
        return EncryptPrivateMessage({
            group_id: this.#groupContext.group_id,
            epoch: this.#groupContext.epoch,
            authenticated_data: new Uint8Array(0),
            cipher_suite: this.#groupContext.cipher_suite,
            sender: {
                sender_type: SenderType.member,
                leaf_index: this.#leafIndex
            },
            content: message,
            wire_format: WireFormat.mls_private_message,
            group_context: this.#groupContext,
            generation,
            nonce,
            key,
            sender_data_secret,
            signature_key
        });
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
        if (
            !(await VerifyWithLabel(
                signatureKey,
                new TextEncoder().encode("KeyPackageTBS"),
                signatureContent,
                signature,
                keyPackage.cipher_suite
            ))
        ) {
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
        // TODO: validate credential
        // validate signature
        const signatureContent = ConstructLeafNodeSignatureData(
            node,
            leaf_index != null ? groupContext.group_id : undefined,
            leaf_index ?? undefined
        );
        const signature = node.signature;
        if (signature == null) {
            throw new InvalidObjectError("Signature is missing");
        }
        const signatureKey = node.signature_key;
        if (!(await VerifyWithLabel(signatureKey, new TextEncoder().encode("LeafNodeTBS"), signatureContent, signature, cipherSuite))) {
            throw new InvalidObjectError("Invalid signature");
        }
        // validate compatibility with group context
        const requiredCapabilities = groupContext.extensions.find(
            (e) => e.extension_type === ExtensionType.required_capabilities
        ) as Extension<ExtensionType.required_capabilities>;
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
        for (const leaf of groupLeaves.map((l) => l.data as LeafNode)) {
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
        // if this is coming from an update proposal, verify that thew new encryption_key is different than the previous one
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
        for (const leaf of groupLeaves.map((l) => l.data as LeafNode)) {
            uniqueKeys.push(leaf.signature_key);
            uniqueKeys.push(leaf.encryption_key);
        }
        if (!uniqueKeys.every((k) => !ArraysEqual(k, node.signature_key) && !ArraysEqual(k, node.encryption_key))) {
            throw new InvalidObjectError("Signature key or encryption key is not unique");
        }
        return true;
    }

    async processAddProposal(proposal: AddProposal, ratchetTree: RatchetTree) {
        // add the new leaf node to the tree
        const addedNode = ratchetTree.addLeaf(proposal.key_package.leaf_node);
        // set unmerged_leaves for each non-blank intermediate node along the direct path
        const intermediates = addedNode.directPath().filter(n => n.data != null);
        intermediates.pop();
        for (const node of intermediates) {
            if (node.data == null) {
                continue;
            }
            const nodeData = ratchetTree.assertParentNode(node);
            nodeData.unmerged_leaves.push(addedNode.index / 2);
            // make sure unmerged_leaves is sorted in ascending order
            nodeData.unmerged_leaves.sort((a, b) => a - b);
            ratchetTree.setNode(node.index, nodeData);
        }
    }

    async processUpdateProposal(proposal: UpdateProposal, leaf_index: Uint32, ratchetTree: RatchetTree) {
        // update the leaf node in the tree
        ratchetTree.setNode(leaf_index.value, proposal.leaf_node);
        // blank intermediate nodes
        const nodes = this.#ratchetTree.directPath(ratchetTree.getIndexedNode(leaf_index.value));
        nodes.pop();
        for (const node of nodes) {
            ratchetTree.setNode(node.index, undefined);
        }
    }

    async processRemoveProposal(proposal: RemoveProposal, ratchetTree: RatchetTree) {
        // remove the leaf node from the tree
        ratchetTree.setNode(proposal.removed.value, undefined);
        // blank all intermediate nodes
        const nodes = this.#ratchetTree.directPath(ratchetTree.getIndexedNode(proposal.removed.value));
        nodes.pop();
        for (const node of nodes) {
            ratchetTree.setNode(node.index, undefined);
        }
        // Truncate the tree by removing the right subtree until there is at least one non-blank leaf node in the right subtree. If the rightmost non-blank leaf has index L, then this will result in the tree having 2d leaves, where d is the smallest value such that 2^d > L.
        const lastNonBlankLeaf = ratchetTree.lastNonBlankLeaf;
        if (lastNonBlankLeaf == null) {
            throw new Error("No non-blank leaf nodes");
        }
        const leafIndex = lastNonBlankLeaf.index / 2;
        let d = 0;
        while (leafIndex >= (1 << d)) {
            d++;
        }
        while (ratchetTree.leafCount !== (1 << d)) {
            ratchetTree.truncate();
        }
    }

    // async createProposal(proposal: Proposal) {
    //     // construct a framed content
    //     const framedContent = {
    //         group_id: this.#groupContext.group_id,
    //         epoch: this.#groupContext.epoch,
    //         sender: {
    //             sender_type: SenderType.member,
    //             leaf_index: this.#ourIndex
    //         },
    //     } satisfies FramedContent;
    // }

    async validateProposalList(proposals: ProposalFrom[]) {
        const addedSignatureKeys = new Array<string>();
        const updatedLeafNodes = new Array<number>();
        const removedLeafNodes = new Array<number>();
        // first check if there is any individual proposals that are not valid
        for (const proposal of proposals) {
            if (IsAddProposal(proposal)) {
                // validate key package
                const keyPackageValid = await this.validateKeyPackage(proposal.key_package).catch(() => false);
                if (!keyPackageValid) {
                    return false;
                }
                addedSignatureKeys.push(bytesToHex(proposal.key_package.leaf_node.signature_key));
            }
            if (IsUpdateProposal(proposal)) {
                // assert that the updated leaf node is ours
                if (proposal.proposal_from.value === this.#leafIndex.value) {
                    return false;
                }
                // validate leaf node
                const prev_leaf_node = this.#ratchetTree.getIndexedNode(proposal.proposal_from.value * 2);
                if (prev_leaf_node.data == null) {
                    return false;
                }
                const leafNodeValid = await this.validateLeafNode(proposal.leaf_node, LeafNodeSource.update, proposal.proposal_from, prev_leaf_node.data as LeafNode).catch(() => false);
                if (!leafNodeValid) {
                    return false;
                }
                updatedLeafNodes.push(proposal.proposal_from.value);
            }
            if (IsRemoveProposal(proposal)) {
                // assert that the removed leaf node is ours
                if (proposal.removed.value === this.#leafIndex.value) {
                    return false;
                }
                // assert that the removed leaf node is non-blank
                const node = this.#ratchetTree.getIndexedNode(proposal.removed.value * 2);
                if (node.data == null) {
                    return false;
                }
                removedLeafNodes.push(proposal.removed.value);
            }
        }
        // check for update/remove proposals that apply to the same leaf node
        const updateRemoveSet = new Set([...updatedLeafNodes, ...removedLeafNodes]);
        if (updateRemoveSet.size !== updatedLeafNodes.length + removedLeafNodes.length) {
            return false;
        }
        // check for add proposals that add the same user
        const addSet = new Set(addedSignatureKeys);
        if (addSet.size !== addedSignatureKeys.length) {
            return false;
        }
        // TODO: complete the rest of the checks
        return true;
    }

    async applyProposalList(proposals: ProposalFrom[]) {
        const newRatchetTree = this.#ratchetTree.clone();
        // apply update proposals
        const updateProposals = proposals.filter(IsUpdateProposal);
        for (const proposal of updateProposals) {
            await this.processUpdateProposal(proposal as UpdateProposal, proposal.proposal_from, newRatchetTree);
        }
        // apply remove proposals
        const removeProposals = proposals.filter(IsRemoveProposal);
        for (const proposal of removeProposals) {
            await this.processRemoveProposal(proposal as RemoveProposal, newRatchetTree);
        }
        // apply add proposals
        const addProposals = proposals.filter(IsAddProposal);
        for (const proposal of addProposals) {
            await this.processAddProposal(proposal as AddProposal, newRatchetTree);
        }
        this.#ratchetTree = newRatchetTree;
    }

    async createCommit(proposals: Proposal[], signature_key: Uint8Array) {
        const finalProposals = new Array<ProposalFrom>();
        finalProposals.push(...this.#cachedProposals);
        finalProposals.push(...proposals.map((p) => ({ ...p, proposal_from: this.#leafIndex })));
        this.#cachedProposals.length = 0;
        // validate the proposals
        if (!await this.validateProposalList(finalProposals)) {
            throw new Error("Invalid proposals");
        }
        const newRatchetTree = this.#ratchetTree.clone();
        let newGroupContext = {
            ...this.#groupContext,
            epoch: this.#groupContext.epoch.add(Uint64.from(1n))
        } satisfies GroupContext;
        await this.applyProposalList(finalProposals);
        const shouldPopulatePath = finalProposals.some(p => IsUpdateProposal(p) || IsRemoveProposal(p));
        let path: UpdatePath | undefined = undefined;
        let commit_secret: Uint8Array | undefined = undefined;
        // perform the direct path update, if needed
        if (shouldPopulatePath) {
            const pathSecrets = await newRatchetTree.updateDirectPath(newRatchetTree.getIndexedNode(this.#leafIndex.value / 2), this.#groupContext, signature_key, this.#groupContext.cipher_suite);
            commit_secret = await DeriveSecret(pathSecrets.at(-1) as Uint8Array, new TextEncoder().encode("path"), this.#groupContext.cipher_suite);
            newGroupContext= {
                ...newGroupContext,
                tree_hash: await newRatchetTree.hash(newRatchetTree.root, this.#groupContext.cipher_suite)
            } satisfies GroupContext;
            path = await newRatchetTree.encryptPathSecrets(newRatchetTree.getIndexedNode(this.#leafIndex.value / 2), pathSecrets, newGroupContext, this.#groupContext.cipher_suite);

        }
        const commit = {
            proposals: finalProposals.map(p => ({ proposal: p, type: ProposalOrRefType.proposal } satisfies ProposalOrRefProposal)),
            path
        } satisfies Commit;
        const suite = DecodeCipherSuiteType(this.#groupContext.cipher_suite);
        if(commit_secret == null) {
            commit_secret = new Uint8Array(suite.kdf.hashSize).fill(0);
        }
        await ConstructFramedContentCommit({
            group_id: this.#groupContext.group_id,
            epoch: this.#groupContext.epoch,
            sender: {
                sender_type: SenderType.member,
                leaf_index: this.#leafIndex
            },
            commit,
            wire_format: WireFormat.mls_private_message,
            group_context: this.#groupContext,
            signature_key: signature_key,
            cipher_suite: this.#groupContext.cipher_suite,
            authenticated_data: new Uint8Array([0xde, 0xad, 0xbe, 0xef])
        })
    }

    /**
     * Create a new group with the given parameters.
     * After the group is created, the DS will be contacted and the function will fail if the DS rejects the group.
     */
    static async create(
        signatureKeyPub: Uint8Array,
        signatureKeyPriv: Uint8Array,
        credential: Credential,
        clientExtensions: Extension<ExtensionType.application_id>[],
        groupExtensions: Extension<ExtensionType.required_capabilities>[],
        cipherSuite: CipherSuiteType
    ) {
        const suite = DecodeCipherSuiteType(cipherSuite);
        // construct our leaf node
        const { node: leafNode, nodePrivateKey } = await GenerateLeafNode({
            cipherSuite,
            signingKeyPriv: signatureKeyPriv,
            signingKeyPub: signatureKeyPub,
            credential,
            extensions: clientExtensions,
            validFor: 86400n
        });
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
        const keySchedule = await KeySchedule.fromEpochSecret(epochSecret, cipherSuite, 1);
        const group = new Group(ratchetTree, groupContext, keySchedule);
        group.#leafIndex = Uint32.from(0);
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
            nodePrivateKey
        };
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

const cipherSuite = CipherSuiteType.MLS_256_DHKEMP384_AES256GCM_SHA384_P384;
const signingKeyPairAlice = await GenerateSigningKeyPair(cipherSuite);
const credentialAlice = {
    credential_type: CredentialType.basic,
    identity: new TextEncoder().encode("testAlice")
} satisfies Credential;
const { group, nodePrivateKey: nodePrivateKeyAlice } = await Group.create(
    signingKeyPairAlice.publicKey,
    signingKeyPairAlice.privateKey,
    credentialAlice,
    [],
    [],
    cipherSuite
);
const messageRaw = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
const message1 = await group.sendMessage(messageRaw, signingKeyPairAlice.privateKey);
const message2 = await group.sendMessage(messageRaw, signingKeyPairAlice.privateKey);
console.log(EncodeMLSMessage(message1));
console.log(EncodeMLSMessage(message2));
