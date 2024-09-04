import { Encoder } from "../Encoding";
import { SenderType } from "../Enums";
import {
    EncodeFramedContent,
    EncodeFramedContentAuthData,
    IsFramedContent,
    IsFramedContentAuthData,
    type FramedContent,
    type FramedContentAuthData
} from "../Message";

interface PublicMessageBase {
    content: FramedContent;
    auth: FramedContentAuthData;
}

interface PublicMessageMember extends PublicMessageBase {
    membership_tag: Uint8Array;
}

type PublicMessage = PublicMessageMember | PublicMessageBase;

function IsPublicMessageBase(object: unknown): object is PublicMessageBase {
    return (
        typeof object === "object" &&
        object !== null &&
        "auth" in object &&
        "content" in object &&
        IsFramedContent(object.content) &&
        IsFramedContentAuthData(object.auth, object.content.content_type)
    );
}

function IsPublicMessageMember(object: unknown): object is PublicMessageMember {
    if (!IsPublicMessageBase(object)) {
        return false;
    }
    return (
        // content.sender.sender_type is member
        object.content.sender.sender_type === SenderType.member && "membership_tag" in object && object.membership_tag instanceof Uint8Array
    );
}

function IsPublicMessage(object: unknown): object is PublicMessage {
    return IsPublicMessageBase(object) || IsPublicMessageMember(object);
}

function EncodePublicMessage(message: PublicMessage) {
    const encoder = new Encoder();
    encoder.writeUint8Array(EncodeFramedContent(message.content), false);
    encoder.writeUint8Array(EncodeFramedContentAuthData(message.auth, message.content.content_type), false);
    return encoder.flush();
}

export type { PublicMessage };
export { IsPublicMessage, EncodePublicMessage };
