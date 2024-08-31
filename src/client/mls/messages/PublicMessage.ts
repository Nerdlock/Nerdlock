import { SenderType } from "../Enums";
import { type FramedContent } from "../Message";
import VarVector from "../types/VarVector";

interface PublicMessageBase {
    content: FramedContent;
}

interface PublicMessageMember extends PublicMessageBase {
    membership_tag: VarVector;
}

type PublicMessage = PublicMessageMember | PublicMessageBase;

function IsPublicMessageBase(object: unknown): object is PublicMessageBase {
    return typeof object === "object" && object !== null;
}

function IsPublicMessageMember(object: unknown): object is PublicMessageMember {
    if (!IsPublicMessageBase(object)) {
        return false;
    }
    return (
        // content.sender.sender_type is member
        object.content.sender.sender_type === SenderType.member &&
        // membership_tag is VarVector
        "membership_tag" in object &&
        object.membership_tag instanceof VarVector &&
        object.membership_tag !== null &&
        // only fields are membership_tag, content and auth
        Object.keys(object).length === 3
    );
}

function IsPublicMessage(object: unknown): object is PublicMessage {
    return IsPublicMessageBase(object) || IsPublicMessageMember(object);
}

export type { PublicMessage };
export { IsPublicMessage };
