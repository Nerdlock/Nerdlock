import type { Commit } from "../Commit";
import { DecodeCipherSuiteType, ExpandWithLabel } from "../CryptoHelper";
import { Encoder } from "../Encoding";
import { ContentType, ProtocolVersion, WireFormat } from "../Enums";
import { ConstructAuthenticatedFramedContentApplication, ConstructAuthenticatedFramedContentProposal, EncodeFramedContentAuthData, IsFramedContentAuthData, type ConstructAuthenticatedFramedContentParamsBase, type FramedContent, type FramedContentAuthData, type MLSMessage, type SenderMember } from "../Message";
import { EncodeProposal, IsProposal, type Proposal } from "../Proposal";
import Uint16 from "../types/Uint16";
import type Uint32 from "../types/Uint32";
import type Uint64 from "../types/Uint64";
import Uint8 from "../types/Uint8";
import VarVector from "../types/VarVector";

interface PrivateMessage {
    group_id: VarVector;
    epoch: Uint64;
    content_type: ContentType;
    authenticated_data: VarVector;
    encrypted_sender_data: VarVector;
    ciphertext: VarVector;
}

function IsPrivateMessage(object: unknown): object is PrivateMessage {
    return typeof object === "object" && object !== null;
}

export { IsPrivateMessage };
export type { PrivateMessage };

interface PrivateMessageContentBase {
    auth: FramedContentAuthData;
    padding: Uint8Array;
}

interface PrivateMessageContentApplication extends PrivateMessageContentBase {
    application_data: Uint8Array;
}

interface PrivateMessageContentProposal extends PrivateMessageContentBase {
    proposal: Proposal;
}

interface PrivateMessageContentCommit extends PrivateMessageContentBase {
    commit: Commit;
}

type PrivateMessageContent = PrivateMessageContentApplication | PrivateMessageContentProposal | PrivateMessageContentCommit;

function IsPrivateMessageContentBase(object: unknown, contentType: ContentType): object is PrivateMessageContentBase {
    return (
        typeof object === "object" &&
        object !== null &&
        "auth" in object &&
        "padding" in object &&
        IsFramedContentAuthData(object.auth, contentType) &&
        object.padding instanceof Uint8Array
    );
}

function IsPrivateMessageContentApplication(object: unknown, contentType: ContentType): object is PrivateMessageContentApplication {
    if (!IsPrivateMessageContentBase(object, contentType)) {
        return false;
    }
    return (
        "application_data" in object &&
        object.application_data instanceof Uint8Array
    );
}

function IsPrivateMessageContentProposal(object: unknown, contentType: ContentType): object is PrivateMessageContentProposal {
    if (!IsPrivateMessageContentBase(object, contentType)) {
        return false;
    }
    return (
        "proposal" in object &&
        IsProposal(object.proposal)
    );
}

function IsPrivateMessageContentCommit(object: unknown, contentType: ContentType): object is PrivateMessageContentCommit {
    if (!IsPrivateMessageContentBase(object, contentType)) {
        return false;
    }
    return (true
        //"commit" in object &&
        //IsCommit(object.commit)
    );
}

function IsPrivateMessageContent(object: unknown, contentType: ContentType): object is PrivateMessageContent {
    return IsPrivateMessageContentApplication(object, contentType) || IsPrivateMessageContentProposal(object, contentType) || IsPrivateMessageContentCommit(object, contentType);
}

interface EncryptPrivateMessageParams extends ConstructAuthenticatedFramedContentParamsBase {
    content: PrivateMessageContent;
    content_type: ContentType;
    key: Uint8Array;
    nonce: Uint8Array;
    generation: Uint32;
    sender_data_secret: Uint8Array;
    wire_format: WireFormat.mls_private_message;
    sender: SenderMember;
}
async function EncryptPrivateMessage(params: EncryptPrivateMessageParams) {
    const { group_id, epoch, sender, authenticated_data, content, cipher_suite, content_type, nonce, key, generation, sender_data_secret, wire_format } = params;
    if (!IsPrivateMessageContent(params.content, content_type)) {
        throw new Error("Invalid content type");
    }
    // step 1: construct the content to be encrypted
    const encoder = new Encoder();
    let framedContentPromise: Promise<{ framedContent: FramedContent, framedContentAuthData: FramedContentAuthData }> | undefined = undefined;
    if (IsPrivateMessageContentApplication(content, content_type)) {
        encoder.writeUint8Array(content.application_data);
        framedContentPromise = ConstructAuthenticatedFramedContentApplication({ ...params, application_data: content.application_data, wire_format });
    }
    else if (IsPrivateMessageContentProposal(content, content_type)) {
        encoder.writeUint8Array(EncodeProposal(content.proposal), false);
        framedContentPromise = ConstructAuthenticatedFramedContentProposal({ ...params, proposal: content.proposal, wire_format });
    }
    else if (IsPrivateMessageContentCommit(params.content, content_type)) {
        //encoder.writeUint8Array(EncodeCommit(params.content.commit), false);
    }
    if (framedContentPromise == null) {
        throw new Error("Invalid content type");
    }
    const { framedContentAuthData } = await framedContentPromise;
    encoder.writeUint8Array(EncodeFramedContentAuthData(framedContentAuthData, content_type), false);
    // generate a padding of all 0 bytes
    // random length from 4 to 32 bytes
    const paddingLength = crypto.getRandomValues(new Uint8Array(4)).reduce((acc, cur) => acc + cur, 0) % (32 - 4) + 4;
    const padding = new Uint8Array(paddingLength).fill(0);
    encoder.writeUint8Array(padding, false);
    const encodedMessage = encoder.flush();
    // to prevent reuse for the nonce, generate 4 random bytes and XOR them with the nonce's first 4 bytes
    const reuseGuard = crypto.getRandomValues(new Uint8Array(4));
    for (let i = 0; i < reuseGuard.length; i++) {
        nonce[i] ^= reuseGuard[i];
    }
    // construct the AAD
    encoder.writeUint8Array(group_id);
    encoder.writeUint(epoch);
    encoder.writeUint(Uint8.from(content_type));
    encoder.writeUint8Array(authenticated_data);
    const messageAAD = encoder.flush();
    // encrypt the message
    const suite = DecodeCipherSuiteType(cipher_suite);
    const ciphertext = await suite.aead.createEncryptionContext(key.buffer as ArrayBuffer).seal(nonce.buffer as ArrayBuffer, encodedMessage.buffer as ArrayBuffer, messageAAD.buffer as ArrayBuffer).then((r) => new Uint8Array(r));
    // create the sender data
    encoder.writeUint(sender.leaf_index)
    encoder.writeUint(generation);
    encoder.writeUint8Array(reuseGuard, false);
    const senderData = encoder.flush();
    // now generate the key and nonce for the sender data
    const ciphertext_sample = new Uint8Array(suite.kdf.hashSize);
    // copy the ciphertext into the ciphertext_sample
    ciphertext_sample.set(ciphertext);
    const sender_data_key = await ExpandWithLabel(sender_data_secret, new TextEncoder().encode("key"), ciphertext_sample, Uint16.from(suite.aead.keySize), cipher_suite);
    const sender_data_nonce = await ExpandWithLabel(sender_data_secret, new TextEncoder().encode("nonce"), ciphertext_sample, Uint16.from(suite.aead.nonceSize), cipher_suite);
    // construct the sender data AAD
    encoder.writeUint8Array(group_id);
    encoder.writeUint(epoch);
    encoder.writeUint(Uint8.from(content_type));
    const senderDataAAD = encoder.flush();
    // encrypt the sender data
    const encrypted_sender_data = await suite.aead.createEncryptionContext(sender_data_key.buffer as ArrayBuffer).seal(sender_data_nonce.buffer as ArrayBuffer, senderData.buffer as ArrayBuffer, senderDataAAD.buffer as ArrayBuffer).then((r) => new Uint8Array(r));
    const message = {
        group_id,
        epoch,
        content_type,
        authenticated_data,
        encrypted_sender_data,
        ciphertext
    } satisfies PrivateMessage;
    return {
        version: ProtocolVersion.mls10,
        wire_format,
        private_message: message
    } satisfies MLSMessage;
}

export { EncryptPrivateMessage, IsPrivateMessageContent, IsPrivateMessageContentApplication, IsPrivateMessageContentCommit, IsPrivateMessageContentProposal };
export type { PrivateMessageContent };

