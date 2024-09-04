import ArrayTree, { type IndexedType } from "./ArrayTree";
import { DecodeCipherSuiteType, ExpandWithLabel } from "./CryptoHelper";
import type { CipherSuiteType } from "./Enums";
import Uint16 from "./types/Uint16";
import Uint32 from "./types/Uint32";

interface SecretRatchet {
    generation: Uint32;
    secret: Uint8Array;
}
type SecretTreeLeaf = { handshake_ratchet: SecretRatchet; application_ratchet: SecretRatchet };
type SecretTreeNode = Uint8Array | SecretTreeLeaf;

interface MessageSecret {
    key: Uint8Array;
    nonce: Uint8Array;
    generation: Uint32;
}
type MessageSecretReturn<T extends Uint32 | undefined> = T extends Uint32 ? MessageSecret[] : MessageSecret;

export type { MessageSecret };

const leftLabel = new TextEncoder().encode("left");
const rightLabel = new TextEncoder().encode("right");
const treeLabel = new TextEncoder().encode("tree");
const handshakeLabel = new TextEncoder().encode("handshake");
const applicationLabel = new TextEncoder().encode("application");
const keyLabel = new TextEncoder().encode("key");
const nonceLabel = new TextEncoder().encode("nonce");
const secretLabel = new TextEncoder().encode("secret");

export default class SecretTree extends ArrayTree<SecretTreeNode> {
    #cipherSuite: CipherSuiteType;

    constructor(leafCount: number, cipherSuite: CipherSuiteType) {
        super(leafCount);
        this.#cipherSuite = cipherSuite;
    }

    async #calculateLeafSecret(node: IndexedType<SecretTreeNode>, cipherSuite: CipherSuiteType) {
        if (this.level(node) !== 0) {
            throw new Error("Node is not a leaf");
        }
        if (node.data instanceof Uint8Array) {
            return node.data;
        }
        // calculate the leaf secret by going down from the root to the leaf node and performing the KDF for each parent node
        const parentSecretNodes = this.directPath(node)
            .toReversed()
            .filter((n) => n.data != null);
        if (parentSecretNodes.length !== 0) {
            throw new Error("No parent secret nodes, unable to calculate leaf secret");
        }
        const suite = DecodeCipherSuiteType(cipherSuite);
        for (const parent of parentSecretNodes) {
            const secret = this.getIndexedNode(parent.index).data as Uint8Array;
            if (secret == null) {
                throw new Error("Parent secret is null");
            }
            const leftSecret = await ExpandWithLabel(secret, treeLabel, leftLabel, Uint16.from(suite.kdf.hashSize), cipherSuite);
            const rightSecret = await ExpandWithLabel(secret, treeLabel, rightLabel, Uint16.from(suite.kdf.hashSize), cipherSuite);
            this.setNode(parent.left().index, leftSecret);
            this.setNode(parent.right().index, rightSecret);
            this.setNode(node.index, undefined);
        }
        // now we should have the leaf secret
        return this.getIndexedNode(node.index).data as Uint8Array;
    }

    async getMessageSecret<T extends Uint32 | undefined>(
        node: IndexedType<SecretTreeNode>,
        type: "handshake" | "application",
        cipherSuite: CipherSuiteType,
        until: T
    ): Promise<MessageSecretReturn<T>> {
        // check if we only have the secret, not the ratchets
        let nodeSecret = node.data;
        if (nodeSecret == null) {
            nodeSecret = await this.#calculateLeafSecret(node, cipherSuite);
        }
        const suite = DecodeCipherSuiteType(cipherSuite);
        if (nodeSecret instanceof Uint8Array) {
            // calculate the ratchets
            const handshake_secret = await ExpandWithLabel(
                nodeSecret,
                handshakeLabel,
                new Uint8Array(0),
                Uint16.from(suite.kdf.hashSize),
                cipherSuite
            );
            const application_secret = await ExpandWithLabel(
                nodeSecret,
                applicationLabel,
                new Uint8Array(0),
                Uint16.from(suite.kdf.hashSize),
                cipherSuite
            );
            this.setNode(node.index, {
                handshake_ratchet: { generation: Uint32.from(0), secret: handshake_secret },
                application_ratchet: { generation: Uint32.from(0), secret: application_secret }
            } satisfies SecretTreeLeaf);
        }
        // we should have the ratchets now
        const ratchets = this.getIndexedNode(node.index).data as SecretTreeLeaf;
        const ratchet = type === "handshake" ? ratchets.handshake_ratchet : ratchets.application_ratchet;
        const generateUntil = until ?? ratchet.generation.add(Uint32.from(1));
        // do until validation: it must not be less than the current generation
        if (generateUntil.value < ratchet.generation.value) {
            throw new Error("Generate until is less than the current generation");
        }
        const secrets = new Array<MessageSecret>();
        for (let i = ratchet.generation.value; i <= generateUntil.value; i++) {
            const nonce = await ExpandWithLabel(
                ratchet.secret,
                nonceLabel,
                Uint32.from(i).encode(),
                Uint16.from(suite.aead.nonceSize),
                cipherSuite
            );
            const key = await ExpandWithLabel(
                ratchet.secret,
                keyLabel,
                Uint32.from(i).encode(),
                Uint16.from(suite.aead.keySize),
                cipherSuite
            );
            secrets.push({ key, nonce, generation: Uint32.from(i) });
            const newSecret = await ExpandWithLabel(
                ratchet.secret,
                secretLabel,
                Uint32.from(i).encode(),
                Uint16.from(suite.kdf.hashSize),
                cipherSuite
            );
            ratchet.secret = newSecret;
        }
        ratchet.generation = generateUntil;
        if (type === "handshake") {
            ratchets.handshake_ratchet = ratchet;
        } else {
            ratchets.application_ratchet = ratchet;
        }
        this.setNode(node.index, ratchets);
        return <MessageSecretReturn<T>>secrets;
    }

    static fromLength(leafCount: number, cipherSuite: CipherSuiteType) {
        const tree = new SecretTree(leafCount, cipherSuite);
        return tree;
    }
}
