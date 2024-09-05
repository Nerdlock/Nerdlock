import { Decoder, Encoder } from "./Encoding";
import type { ProposalOrRefType } from "./Enums";
import InvalidObjectError from "./errors/InvalidObjectError";
import type { Proposal } from "./Proposal";
import { DecodeLeafNode, EncodeLeafNode, IsLeafNode, type LeafNode } from "./RatchetTree";
import type Uint32 from "./types/Uint32";

interface HPKECipherText {
    kem_output: Uint8Array;
    ciphertext: Uint8Array;
}

function IsHPKECipherText(object: unknown): object is HPKECipherText {
    return (
        typeof object === "object" &&
        object !== null &&
        "kem_output" in object &&
        object.kem_output instanceof Uint8Array &&
        "ciphertext" in object &&
        object.ciphertext instanceof Uint8Array
    );
}

interface UpdatePathNode {
    encryption_key: Uint8Array;
    encrypted_path_secret: HPKECipherText;
}

function IsUpdatePathNode(object: unknown): object is UpdatePathNode {
    return (
        typeof object === "object" &&
        object !== null &&
        "encryption_key" in object &&
        object.encryption_key instanceof Uint8Array &&
        "encrypted_path_secret" in object &&
        IsHPKECipherText(object.encrypted_path_secret)
    );
}

interface UpdatePath {
    leaf_node: LeafNode;
    nodes: UpdatePathNode[];
}

function IsUpdatePath(object: unknown): object is UpdatePath {
    return (
        typeof object === "object" &&
        object !== null &&
        "leaf_node" in object &&
        IsLeafNode(object.leaf_node) &&
        "nodes" in object &&
        object.nodes instanceof Array &&
        object.nodes.every((n) => IsUpdatePathNode(n))
    );
}

function EncodeUpdatePath(path: UpdatePath) {
    const encoder = new Encoder();
    encoder.writeUint8Array(EncodeLeafNode(path.leaf_node), false);
    encoder.writeArray(path.nodes, (n, encoder) => {
        encoder.writeUint8Array(n.encryption_key);
        encoder.writeUint8Array(n.encrypted_path_secret.kem_output);
        encoder.writeUint8Array(n.encrypted_path_secret.ciphertext);
    });
    return encoder.flush();
}

function DecodeUpdatePath(decoder: Decoder): UpdatePath {
    const leaf_node = DecodeLeafNode(decoder);
    const nodes = decoder.readArray<UpdatePathNode>((decoder) => {
        const encryption_key = decoder.readUint8Array();
        const encrypted_path_secret = {
            kem_output: decoder.readUint8Array(),
            ciphertext: decoder.readUint8Array()
        } satisfies HPKECipherText;
        if (!IsHPKECipherText(encrypted_path_secret)) {
            throw new InvalidObjectError("Invalid HPKE cipher text");
        }
        const node = {
            encryption_key,
            encrypted_path_secret
        } satisfies UpdatePathNode;
        if (!IsUpdatePathNode(node)) {
            throw new InvalidObjectError("Invalid update path node");
        }
        return node;
    });
    const path = {
        leaf_node,
        nodes
    } satisfies UpdatePath;
    if (!IsUpdatePath(path)) {
        throw new InvalidObjectError("Invalid update path");
    }
    return path;
}

export type { UpdatePath, UpdatePathNode };

interface ProposalOrRefBase {
    type: ProposalOrRefType;
}

interface ProposalOrRefProposal extends ProposalOrRefBase {
    type: ProposalOrRefType.proposal;
    proposal: Proposal;
}

interface ProposalOrRefReference extends ProposalOrRefBase {
    type: ProposalOrRefType.reference;
    reference: Uint32;
}

type ProposalOrRef = ProposalOrRefProposal | ProposalOrRefReference;

interface Commit {
    proposals: ProposalOrRef[];
    path?: UpdatePath;
}

export type { Commit, ProposalOrRefProposal };
