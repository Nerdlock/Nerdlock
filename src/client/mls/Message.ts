import type { Commit } from "./Commit";
import { SignWithLabel } from "./CryptoHelper";
import { Decoder, Encoder } from "./Encoding";
import { CipherSuiteType, ContentType, ProtocolVersion, SenderType, WireFormat } from "./Enums";
import MalformedObjectError from "./errors/MalformedObjectError";
import { EncodeGroupContext, type GroupContext } from "./GroupContext";
import { IsGroupInfo, type GroupInfo } from "./messages/GroupInfo";
import { EncodeKeyPackage, IsKeyPackage, type KeyPackage } from "./messages/KeyPackage";
import { EncodePrivateMessage, IsPrivateMessage, type PrivateMessage } from "./messages/PrivateMessage";
import { EncodePublicMessage, IsPublicMessage, type PublicMessage } from "./messages/PublicMessage";
import { IsWelcome, type Welcome } from "./messages/Welcome";
import { IsProposal, type Proposal } from "./Proposal";
import Uint16 from "./types/Uint16";
import Uint32 from "./types/Uint32";
import Uint64 from "./types/Uint64";
import Uint8 from "./types/Uint8";

interface SenderBase {
    sender_type: SenderType;
}

interface SenderMember extends SenderBase {
    sender_type: SenderType.member;
    leaf_index: Uint32;
}

interface SenderExternal extends SenderBase {
    sender_type: SenderType.external;
    sender_index: Uint32;
}

interface SenderNewMemberProposal extends SenderBase {
    sender_type: SenderType.new_member_proposal;
}

interface SenderNewMemberCommit extends SenderBase {
    sender_type: SenderType.new_member_commit;
}

type Sender = SenderMember | SenderExternal | SenderNewMemberProposal | SenderNewMemberCommit;

function IsSenderBase(object: unknown): object is SenderBase {
    return typeof object === "object" && object !== null && "sender_type" in object && typeof object.sender_type === "number";
}

function IsSenderMember(object: unknown): object is SenderMember {
    if (!IsSenderBase(object)) {
        return false;
    }
    // sender_type is SenderType.member
    return object.sender_type === SenderType.member && "leaf_index" in object && object.leaf_index instanceof Uint32;
}

function IsSenderExternal(object: unknown): object is SenderExternal {
    if (!IsSenderBase(object)) {
        return false;
    }
    // sender_type is SenderType.external
    return object.sender_type === SenderType.external && "sender_index" in object && object.sender_index instanceof Uint32;
}

function IsSenderNewMemberProposal(object: unknown): object is SenderNewMemberProposal {
    if (!IsSenderBase(object)) {
        return false;
    }
    // sender_type is SenderType.new_member_proposal
    return object.sender_type === SenderType.new_member_proposal;
}

function IsSenderNewMemberCommit(object: unknown): object is SenderNewMemberCommit {
    if (!IsSenderBase(object)) {
        return false;
    }
    // sender_type is SenderType.new_member_commit
    return object.sender_type === SenderType.new_member_commit;
}

function IsSender(object: unknown): object is Sender {
    return IsSenderMember(object) || IsSenderExternal(object) || IsSenderNewMemberProposal(object) || IsSenderNewMemberCommit(object);
}

function EncodeSender(sender: Sender): Uint8Array {
    const encoder = new Encoder();
    encoder.writeUint(Uint8.from(sender.sender_type));
    const isSenderOrExternal = IsSenderMember(sender) || IsSenderExternal(sender);
    if (isSenderOrExternal) {
        if (IsSenderMember(sender)) {
            encoder.writeUint(sender.leaf_index);
        } else {
            encoder.writeUint(sender.sender_index);
        }
    }
    return new Uint8Array(encoder.flush());
}

function DecodeSender(decoder: Decoder): Sender {
    const senderType = decoder.readUint8().value;
    // validate senderType is one of the values in SenderType
    if (![SenderType.member, SenderType.external, SenderType.new_member_proposal, SenderType.new_member_commit].includes(senderType)) {
        throw new MalformedObjectError("Invalid sender type", "sender_type", senderType);
    }
    if (senderType === SenderType.member) {
        return {
            sender_type: senderType,
            leaf_index: decoder.readUint32()
        } satisfies SenderMember;
    }
    if (senderType === SenderType.external) {
        return {
            sender_type: senderType,
            sender_index: decoder.readUint32()
        } satisfies SenderExternal;
    }
    return {
        sender_type: senderType
    } satisfies Sender;
}

export {
    DecodeSender,
    EncodeSender,
    IsSender,
    IsSenderBase,
    IsSenderExternal,
    IsSenderMember,
    IsSenderNewMemberCommit,
    IsSenderNewMemberProposal
};
export type { Sender, SenderMember };

interface FramedContentBase {
    group_id: Uint8Array;
    epoch: Uint64;
    sender: Sender;
    content_type: ContentType;
    authenticated_data: Uint8Array;
}

interface FramedContentApplication extends FramedContentBase {
    content_type: ContentType.application;
    application_data: Uint8Array;
}

interface FramedContentProposal extends FramedContentBase {
    content_type: ContentType.proposal;
    proposal: Proposal;
}

interface FramedContentCommit extends FramedContentBase {
    content_type: ContentType.commit;
    commit: Commit;
}

type FramedContent = FramedContentApplication | FramedContentProposal | FramedContentCommit;

function IsFramedContentBase(object: unknown): object is FramedContentBase {
    return (
        typeof object === "object" &&
        object !== null &&
        "group_id" in object &&
        "epoch" in object &&
        "sender" in object &&
        "content_type" in object &&
        object.group_id instanceof Uint8Array &&
        object.epoch instanceof Uint64 &&
        IsSender(object.sender) &&
        typeof object.content_type === "number" &&
        "authenticated_data" in object &&
        object.authenticated_data instanceof Uint8Array
    );
}

function IsFramedContentApplication(object: unknown): object is FramedContentApplication {
    if (!IsFramedContentBase(object)) {
        return false;
    }
    // content_type is ContentType.application
    return object.content_type === ContentType.application && "application_data" in object && object.application_data instanceof Uint8Array;
}

function IsFramedContentProposal(object: unknown): object is FramedContentProposal {
    if (!IsFramedContentBase(object)) {
        return false;
    }
    // content_type is ContentType.proposal
    // proposal is Proposal
    return object.content_type === ContentType.proposal && "proposal" in object && IsProposal(object.proposal);
}

function IsFramedContentCommit(object: unknown): object is FramedContentCommit {
    if (!IsFramedContentBase(object)) {
        return false;
    }
    // content_type is ContentType.commit
    // commit is Commit
    return (
        object.content_type === ContentType.commit && "commit" in object //&&
        //IsCommit(object.commit)
    );
}

function IsFramedContent(object: unknown): object is FramedContent {
    return IsFramedContentApplication(object) || IsFramedContentProposal(object) || IsFramedContentCommit(object);
}

/**
 * Encode FrameContent as a Uint8Array without the authenticated data (to be used for the signature)
 * @param content The FramedContent to encode
 * @returns The encoded FramedContent without the authenticated data
 */
function EncodeFramedContent(content: FramedContent) {
    const encoder = new Encoder();
    encoder.writeUint8Array(content.group_id);
    encoder.writeUint(content.epoch);
    encoder.writeUint8Array(EncodeSender(content.sender), false);
    encoder.writeUint(Uint8.from(content.content_type));
    encoder.writeUint8Array(content.authenticated_data);
    if (IsFramedContentApplication(content)) {
        encoder.writeUint8Array(content.application_data);
    }
    return encoder.flush();
}

/**
 * Constructs the raw bytes of an encoded FramedContentTBS structure from a FramedContent object for signing/verification.
 * @param version The version of the MLS protocol to use.
 * @param wireFormat The wire format to use.
 * @param content The FramedContent to encode.
 * @param context The GroupContext to encode, if needed.
 * @returns The raw bytes of an encoded FramedContentTBS structure, ready to be used for signing/verification.
 */
function ConstructFramedContentSignatureData(
    version: ProtocolVersion,
    wireFormat: WireFormat,
    content: FramedContent,
    context?: GroupContext
) {
    const encoder = new Encoder();
    encoder.writeUint(Uint16.from(version));
    encoder.writeUint(Uint16.from(wireFormat));
    encoder.writeUint8Array(EncodeFramedContent(content), false);
    if (content.sender.sender_type === SenderType.member || content.sender.sender_type === SenderType.new_member_commit) {
        if (context == null) {
            throw new Error("Group context is missing");
        }
        encoder.writeUint8Array(EncodeGroupContext(context), false);
    }
    return encoder.flush();
}

// note from Mester: could have the following code been made better? yes. will it? no, lol

interface SignFramedContentParams {
    framedContent: FramedContent;
    wire_format: WireFormat;
    group_context?: GroupContext;
    signature_key: Uint8Array;
    cipher_suite: CipherSuiteType;
}

async function SignFramedContent(params: SignFramedContentParams) {
    const { framedContent, wire_format, group_context, signature_key, cipher_suite } = params;
    const signatureData = ConstructFramedContentSignatureData(ProtocolVersion.mls10, wire_format, framedContent, group_context);
    const signature = await SignWithLabel(signature_key, new TextEncoder().encode("FramedContentTBS"), signatureData, cipher_suite);
    return {
        framedContent,
        framedContentAuthData: {
            signature
        } satisfies FramedContentAuthDataBase
    };
}

interface ConstructFramedContentParamsBase {
    group_id: Uint8Array;
    epoch: Uint64;
    sender: Sender;
    authenticated_data: Uint8Array;
    wire_format: WireFormat;
    group_context?: GroupContext;
    signature_key: Uint8Array;
    cipher_suite: CipherSuiteType;
}

interface ConstructFramedContentParamsApplication extends ConstructFramedContentParamsBase {
    application_data: Uint8Array;
}
async function ConstructFramedContentApplication(params: ConstructFramedContentParamsApplication) {
    const { group_id, epoch, sender, authenticated_data, application_data, wire_format, group_context, signature_key, cipher_suite } =
        params;
    // first construct the framed content
    const framedContent = {
        group_id,
        epoch,
        sender,
        content_type: ContentType.application,
        authenticated_data,
        application_data
    } satisfies FramedContentApplication;
    return SignFramedContent({ framedContent, wire_format, group_context, signature_key, cipher_suite });
}

interface ConstructFramedContentParamsProposal extends ConstructFramedContentParamsBase {
    proposal: Proposal;
}
async function ConstructFramedContentProposal(params: ConstructFramedContentParamsProposal) {
    const { group_id, epoch, sender, authenticated_data, proposal, wire_format, group_context, signature_key, cipher_suite } = params;
    // first construct the framed content
    const framedContent = {
        group_id,
        epoch,
        sender,
        content_type: ContentType.proposal,
        authenticated_data,
        proposal
    } satisfies FramedContentProposal;
    return SignFramedContent({ framedContent, wire_format, group_context, signature_key, cipher_suite });
}

interface ConstructFramedContentParamsCommit extends ConstructFramedContentParamsBase {
    commit: Commit;
}

async function ConstructFramedContentCommit(params: ConstructFramedContentParamsCommit) {
    const { group_id, epoch, sender, authenticated_data, commit, wire_format, group_context, signature_key, cipher_suite } =
        params;
    // first construct the framed content
    const framedContent = {
        group_id,
        epoch,
        sender,
        content_type: ContentType.commit,
        authenticated_data,
        commit
    } satisfies FramedContentCommit;
    return SignFramedContent({ framedContent, wire_format, group_context, signature_key, cipher_suite });
}

export {
    ConstructFramedContentApplication,
    ConstructFramedContentProposal,
    ConstructFramedContentCommit,
    IsFramedContent,
    IsFramedContentApplication,
    IsFramedContentCommit,
    IsFramedContentProposal,
    EncodeFramedContent
};
export type { ConstructFramedContentParamsBase, FramedContent };

interface FramedContentAuthDataBase {
    signature: Uint8Array;
}

interface FramedContentAuthDataCommit extends FramedContentAuthDataBase {
    confirmation_tag: Uint8Array;
}

type FramedContentAuthData = FramedContentAuthDataCommit | FramedContentAuthDataBase;

function IsFramedContentAuthDataBase(object: unknown): object is FramedContentAuthDataBase {
    return typeof object === "object" && object !== null && "signature" in object && object.signature instanceof Uint8Array;
}

function IsFramedContentAuthDataCommit(object: unknown, contentType: ContentType): object is FramedContentAuthDataCommit {
    if (!IsFramedContentAuthDataBase(object)) {
        return false;
    }
    return contentType === ContentType.commit && "confirmation_tag" in object && object.confirmation_tag instanceof Uint8Array;
}

function IsFramedContentAuthData(object: unknown, contentType: ContentType): object is FramedContentAuthData {
    return IsFramedContentAuthDataBase(object) || IsFramedContentAuthDataCommit(object, contentType);
}

function EncodeFramedContentAuthData(auth: FramedContentAuthData, contentType: ContentType) {
    const encoder = new Encoder();
    encoder.writeUint8Array(auth.signature);
    if (IsFramedContentAuthDataCommit(auth, contentType)) {
        encoder.writeUint8Array(auth.confirmation_tag);
    }
    return encoder.flush();
}

export { EncodeFramedContentAuthData, IsFramedContentAuthData };
export type { FramedContentAuthData };

interface AuthenticatedContent {
    wire_format: WireFormat;
    content: FramedContent;
    auth: FramedContentAuthData;
}

function IsAuthenticatedContent(object: unknown): object is AuthenticatedContent {
    return (
        typeof object === "object" &&
        object !== null &&
        "wire_format" in object &&
        "content" in object &&
        "auth" in object &&
        typeof object.wire_format === "number" &&
        IsFramedContent(object.content) &&
        IsFramedContentAuthData(object.auth, object.content.content_type)
    );
}

function EncodeAuthenticatedContent(content: AuthenticatedContent) {
    const encoder = new Encoder();
    encoder.writeUint(Uint16.from(content.wire_format));
    encoder.writeUint8Array(EncodeFramedContent(content.content), false);
    encoder.writeUint8Array(EncodeFramedContentAuthData(content.auth, content.content.content_type), false);
    return encoder.flush();
}

export { EncodeAuthenticatedContent, IsAuthenticatedContent };
export type { AuthenticatedContent };

interface MLSMessageBase {
    version: ProtocolVersion.mls10;
    wire_format: WireFormat;
}

interface MLSMessagePublic extends MLSMessageBase {
    wire_format: WireFormat.mls_public_message;
    public_message: PublicMessage;
}

interface MLSMessagePrivate extends MLSMessageBase {
    wire_format: WireFormat.mls_private_message;
    private_message: PrivateMessage;
}

interface MLSMessageWelcome extends MLSMessageBase {
    wire_format: WireFormat.mls_welcome;
    welcome: Welcome;
}

interface MLSMessageGroupInfo extends MLSMessageBase {
    wire_format: WireFormat.mls_group_info;
    group_info: GroupInfo;
}

interface MLSMessageKeyPackage extends MLSMessageBase {
    wire_format: WireFormat.mls_key_package;
    key_package: KeyPackage;
}

type MLSMessage = MLSMessagePublic | MLSMessagePrivate | MLSMessageWelcome | MLSMessageGroupInfo | MLSMessageKeyPackage;

function IsMLSMessageBase(object: unknown): object is MLSMessageBase {
    // version is ProtocolVersion.mls10
    // wire_format is one of the values in WireFormat, except RESERVED
    return (
        typeof object === "object" &&
        object !== null &&
        "version" in object &&
        "wire_format" in object &&
        typeof object.version === "number" &&
        typeof object.wire_format === "number"
    );
}

function IsMLSMessagePublic(object: unknown): object is MLSMessagePublic {
    if (!IsMLSMessageBase(object)) {
        return false;
    }
    // wire_format is WireFormat.mls_public_message
    // public_message is PublicMessage
    return (
        "wire_format" in object &&
        object.wire_format === WireFormat.mls_public_message &&
        "public_message" in object &&
        IsPublicMessage(object.public_message)
    );
}

function IsMLSMessagePrivate(object: unknown): object is MLSMessagePrivate {
    if (!IsMLSMessageBase(object)) {
        return false;
    }
    // wire_format is WireFormat.mls_private_message
    // private_message is PrivateMessage
    return (
        "wire_format" in object &&
        object.wire_format === WireFormat.mls_private_message &&
        "private_message" in object &&
        IsPrivateMessage(object.private_message)
    );
}

function IsMLSMessageWelcome(object: unknown): object is MLSMessageWelcome {
    if (!IsMLSMessageBase(object)) {
        return false;
    }
    // wire_format is WireFormat.mls_welcome
    // welcome is Welcome
    return "wire_format" in object && object.wire_format === WireFormat.mls_welcome && "welcome" in object && IsWelcome(object.welcome);
}

function IsMLSMessageGroupInfo(object: unknown): object is MLSMessageGroupInfo {
    if (!IsMLSMessageBase(object)) {
        return false;
    }
    // wire_format is WireFormat.mls_group_info
    // group_info is GroupInfo
    return (
        "wire_format" in object &&
        object.wire_format === WireFormat.mls_group_info &&
        "group_info" in object &&
        IsGroupInfo(object.group_info)
    );
}
function IsMLSMessageKeyPackage(object: unknown): object is MLSMessageKeyPackage {
    if (!IsMLSMessageBase(object)) {
        return false;
    }
    // wire_format is WireFormat.mls_key_package
    // key_package is KeyPackage
    return (
        "wire_format" in object &&
        object.wire_format === WireFormat.mls_key_package &&
        "key_package" in object &&
        IsKeyPackage(object.key_package)
    );
}

function IsMLSMessage(object: unknown): object is MLSMessage {
    return (
        IsMLSMessagePublic(object) ||
        IsMLSMessagePrivate(object) ||
        IsMLSMessageWelcome(object) ||
        IsMLSMessageGroupInfo(object) ||
        IsMLSMessageKeyPackage(object)
    );
}

function EncodeMLSMessage(message: MLSMessage) {
    const encoder = new Encoder();
    encoder.writeUint(Uint16.from(message.wire_format));
    if (IsMLSMessagePublic(message)) {
        encoder.writeUint8Array(EncodePublicMessage(message.public_message), false);
    }
    if (IsMLSMessagePrivate(message)) {
        encoder.writeUint8Array(EncodePrivateMessage(message.private_message), false);
    }
    if (IsMLSMessageKeyPackage(message)) {
        encoder.writeUint8Array(EncodeKeyPackage(message.key_package), false);
    }
    return encoder.flush();
}

export {
    IsMLSMessage,
    IsMLSMessageGroupInfo,
    IsMLSMessageKeyPackage,
    IsMLSMessagePrivate,
    IsMLSMessagePublic,
    IsMLSMessageWelcome,
    EncodeMLSMessage
};
export type { MLSMessage };
