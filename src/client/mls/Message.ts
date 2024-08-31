import type { Commit } from "./Commit";
import { SignWithLabel } from "./CryptoHelper";
import { Decoder, Encoder } from "./Encoding";
import { CipherSuiteType, ContentType, ProtocolVersion, SenderType, WireFormat } from "./Enums";
import MalformedObjectError from "./errors/MalformedObjectError";
import { EncodeGroupContext, IsGroupContext, type GroupContext } from "./GroupContext";
import { IsGroupInfo, type GroupInfo } from "./messages/GroupInfo";
import { IsKeyPackage, type KeyPackage } from "./messages/KeyPackage";
import { IsPrivateMessage, type PrivateMessage } from "./messages/PrivateMessage";
import { IsPublicMessage, type PublicMessage } from "./messages/PublicMessage";
import { IsWelcome, type Welcome } from "./messages/Welcome";
import type { Proposal } from "./Proposal";
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
    return (
        typeof object === "object" &&
        object !== null &&
        "sender_type" in object &&
        typeof object.sender_type === "number" &&
        [
            SenderType.member,
            SenderType.external,
            SenderType.new_member_proposal,
            SenderType.new_member_commit
        ].includes(object.sender_type)
    )
}

function IsSenderMember(object: unknown): object is SenderMember {
    if (!IsSenderBase(object)) {
        return false;
    }
    // sender_type is SenderType.member
    return (
        object.sender_type === SenderType.member &&
        "leaf_index" in object &&
        object.leaf_index instanceof Uint32 &&
        Object.keys(object).length === 2
    );
}

function IsSenderExternal(object: unknown): object is SenderExternal {
    if (!IsSenderBase(object)) {
        return false;
    }
    // sender_type is SenderType.external
    return (
        object.sender_type === SenderType.external &&
        "sender_index" in object &&
        object.sender_index instanceof Uint32 &&
        Object.keys(object).length === 2
    );
}

function IsSenderNewMemberProposal(object: unknown): object is SenderNewMemberProposal {
    if (!IsSenderBase(object)) {
        return false;
    }
    // sender_type is SenderType.new_member_proposal
    return (
        object.sender_type === SenderType.new_member_proposal &&
        Object.keys(object).length === 1
    );
}

function IsSenderNewMemberCommit(object: unknown): object is SenderNewMemberCommit {
    if (!IsSenderBase(object)) {
        return false;
    }
    // sender_type is SenderType.new_member_commit
    return (
        object.sender_type === SenderType.new_member_commit &&
        Object.keys(object).length === 1
    );
}

function IsSender(object: unknown): object is Sender {
    return (
        IsSenderMember(object) ||
        IsSenderExternal(object) ||
        IsSenderNewMemberProposal(object) ||
        IsSenderNewMemberCommit(object)
    );
}

function EncodeSender(sender: Sender): Uint8Array {
    const encoder = new Encoder();
    encoder.writeUint8(new Uint8(sender.sender_type));
    const isSenderOrExternal = IsSenderMember(sender) || IsSenderExternal(sender);
    if (isSenderOrExternal) {
        if (IsSenderMember(sender)) {
            encoder.writeUint32(sender.leaf_index);
        } else {
            encoder.writeUint32(sender.sender_index);
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

export { DecodeSender, EncodeSender, IsSender, IsSenderBase, IsSenderExternal, IsSenderMember, IsSenderNewMemberCommit, IsSenderNewMemberProposal };
export type { Sender };

interface FramedContentBase {
    group_id: Uint8Array;
    epoch: Uint64;
    sender: Sender;
    content_type: ContentType;
    // the authenticated_data might not exist, but must be validated when necessary
    authenticated_data?: Uint8Array;
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
        [
            ContentType.application,
            ContentType.proposal,
            ContentType.commit
        ].includes(object.content_type) &&
        // check if authenticated_data field exists
        // it is optional, but if it exists, it must be a Uint8Array
        (("authenticated_data" in object && object.authenticated_data instanceof Uint8Array) || ("authenticated_data" in object && object.authenticated_data === undefined))
    );
}

function IsFramedContentApplication(object: unknown): object is FramedContentApplication {
    if (!IsFramedContentBase(object)) {
        return false;
    }
    // content_type is ContentType.application
    return (
        object.content_type === ContentType.application &&
        "application_data" in object &&
        object.application_data instanceof Uint8Array
    );
}

function IsFramedContentProposal(object: unknown): object is FramedContentProposal {
    if (!IsFramedContentBase(object)) {
        return false;
    }
    // content_type is ContentType.proposal
    // proposal is Proposal
    return (
        object.content_type === ContentType.proposal &&
        "proposal" in object //&&
        //IsProposal(object.proposal)
    );
}

function IsFramedContentCommit(object: unknown): object is FramedContentCommit {
    if (!IsFramedContentBase(object)) {
        return false;
    }
    // content_type is ContentType.commit
    // commit is Commit
    return (
        object.content_type === ContentType.commit &&
        "commit" in object //&&
        //IsCommit(object.commit)
    );
}

function IsFramedContent(object: unknown): object is FramedContent {
    return (
        IsFramedContentApplication(object) ||
        IsFramedContentProposal(object) ||
        IsFramedContentCommit(object)
    );
}

/**
 * Encode FrameContent as a Uint8Array without the authenticated data (to be used for the signature)
 * @param content The FramedContent to encode
 * @returns The encoded FramedContent without the authenticated data
 */
function EncodeFramedContent(content: Omit<FramedContent, "authenticated_data">) {
    const encoder = new Encoder();
    encoder.writeUint8Array(content.group_id);
    encoder.writeUint64(content.epoch);
    encoder.writeUint8Array(EncodeSender(content.sender));
    encoder.writeUint8(Uint8.from(content.content_type));
    if (IsFramedContentApplication(content)) {
        encoder.writeUint8Array(content.application_data);
    }
    return encoder.flush();
}

export { IsFramedContent, IsFramedContentApplication, IsFramedContentCommit, IsFramedContentProposal };
export type { FramedContent };

interface FramedContentTBSBase {
    version: ProtocolVersion.mls10;
    wire_format: WireFormat;
    content: FramedContent;
}

interface FramedContentTBSGroupContext extends FramedContentTBSBase {
    context: GroupContext;
}

type FramedContentTBS = FramedContentTBSGroupContext | FramedContentTBSBase;

function IsFramedContentTBSBase(object: unknown): object is FramedContentTBSBase {
    return (
        typeof object === "object" &&
        object !== null &&
        "version" in object &&
        "wire_format" in object &&
        "content" in object &&
        IsFramedContent(object.content)
    );
}

function IsFramedContentTBSGroupContext(object: unknown): object is FramedContentTBSGroupContext {
    if (!IsFramedContentTBSBase(object)) {
        return false;
    }
    // context is GroupContext
    return (
        "context" in object &&
        IsGroupContext(object.context) &&
        // content.sender.sender_type must be member or new_member_commit
        (
            object.content.sender.sender_type === SenderType.member ||
            object.content.sender.sender_type === SenderType.new_member_commit
        )
    );
}

function IsFramedContentTBSMember(object: unknown): object is FramedContentTBSGroupContext {
    if (!IsFramedContentTBSGroupContext(object)) {
        return false;
    }
    return object.content.sender.sender_type === SenderType.member;
}

function IsFramedContentTBSNewMemberCommit(object: unknown): object is FramedContentTBSGroupContext {
    if (!IsFramedContentTBSGroupContext(object)) {
        return false;
    }
    return object.content.sender.sender_type === SenderType.new_member_commit;
}

function IsFramedContentTBS(object: unknown): object is FramedContentTBS {
    return (
        IsFramedContentTBSMember(object) ||
        IsFramedContentTBSNewMemberCommit(object) ||
        // if the object is just the base, it must only have 3 fields
        (IsFramedContentTBSBase(object) && Object.keys(object).length === 3)
    );
}

/**
 * Encode a FramedContentTBS object to be used for signing
 * @param framedContent The FramedContentTBS to encode
 * @returns The encoded FramedContentTBS, ready to be signed
 */
function EncodeFramedContentTBS(framedContent: FramedContentTBS) {
    const encoder = new Encoder();
    encoder.writeUint16(Uint16.from(framedContent.version));
    encoder.writeUint16(Uint16.from(framedContent.wire_format));
    encoder.writeUint8Array(EncodeFramedContent(framedContent.content));
    if (IsFramedContentTBSGroupContext(framedContent)) {
        encoder.writeUint8Array(EncodeGroupContext(framedContent.context));
    }
    return encoder.flush();
}

export { IsFramedContentTBS, IsFramedContentTBSMember, IsFramedContentTBSNewMemberCommit };
export type { FramedContentTBS };

interface FramedContentAuthDataBase {
    signature: Uint8Array;
}

interface FramedContentAuthDataCommit extends FramedContentAuthDataBase {
    confirmation_tag: Uint8Array;
}

type FramedContentAuthData = FramedContentAuthDataCommit | FramedContentAuthDataBase;

function IsFramedContentAuthDataBase(object: unknown): object is FramedContentAuthDataBase {
    return (
        typeof object === "object" &&
        object !== null &&
        "signature" in object &&
        object.signature instanceof Uint8Array
    )
};

function IsFramedContentAuthDataCommit(object: unknown, contentType: ContentType): object is FramedContentAuthDataCommit {
    if (!IsFramedContentAuthDataBase(object)) {
        return false;
    }
    return (
        contentType === ContentType.commit &&
        "confirmation_tag" in object &&
        object.confirmation_tag instanceof Uint8Array &&
        Object.keys(object).length === 2
    );
}

function IsFramedContentAuthData(object: unknown, contentType: ContentType): object is FramedContentAuthData {
    return (IsFramedContentAuthDataBase(object) || IsFramedContentAuthDataCommit(object, contentType));
}

function EncodeFramedContentAuthData(auth: FramedContentAuthData, contentType: ContentType) {
    const encoder = new Encoder();
    encoder.writeUint8Array(auth.signature);
    if (IsFramedContentAuthDataCommit(auth, contentType)) {
        encoder.writeUint8Array(auth.confirmation_tag);
    }
    return encoder.flush();
}

function ConstructFramedContentAuthDataSignature(key: Uint8Array, framedContentTBS: FramedContentTBS, cipherSuite: CipherSuiteType) {
    const encodedContent = EncodeFramedContentTBS(framedContentTBS);
    return SignWithLabel(key, new TextEncoder().encode("FramedContentTBS"), encodedContent, cipherSuite);
}

export { IsFramedContentAuthData };
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
    encoder.writeUint16(Uint16.from(content.wire_format));
    encoder.writeUint8Array(EncodeFramedContent(content.content));
    encoder.writeUint8Array(EncodeFramedContentAuthData(content.auth, content.content.content_type));
    return encoder.flush();
}

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
        typeof object.wire_format === "number" &&
        object.version === ProtocolVersion.mls10 &&
        [
            WireFormat.mls_public_message,
            WireFormat.mls_private_message,
            WireFormat.mls_welcome,
            WireFormat.mls_group_info,
            WireFormat.mls_key_package
        ].includes(object.wire_format)
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
        &&
        // only fields are version, wire_format, public_message
        Object.keys(object).length === 3
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
        &&
        // only fields are version, wire_format, private_message
        Object.keys(object).length === 3
    );
}

function IsMLSMessageWelcome(object: unknown): object is MLSMessageWelcome {
    if (!IsMLSMessageBase(object)) {
        return false;
    }
    // wire_format is WireFormat.mls_welcome
    // welcome is Welcome
    return (
        "wire_format" in object &&
        object.wire_format === WireFormat.mls_welcome &&
        "welcome" in object &&
        IsWelcome(object.welcome)
        &&
        // only fields are version, wire_format, welcome
        Object.keys(object).length === 3
    );
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
        &&
        // only fields are version, wire_format, group_info
        Object.keys(object).length === 3
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
        &&
        // only fields are version, wire_format, key_package
        Object.keys(object).length === 3
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

export { IsMLSMessage, IsMLSMessageGroupInfo, IsMLSMessageKeyPackage, IsMLSMessagePrivate, IsMLSMessagePublic, IsMLSMessageWelcome };
export type { MLSMessage };
