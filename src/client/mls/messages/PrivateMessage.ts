import type { Commit } from "../Commit";
import { IsFramedContentAuthData, type ContentType, type FramedContentAuthData, type FramedContentTBS } from "../Message";
import type { Proposal } from "../Proposal";
import type Uint64 from "../types/Uint64";
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

export type { PrivateMessage };
export { IsPrivateMessage };

interface PrivateMessageContentBase {
    auth: FramedContentAuthData<FramedContentTBS>;
    padding: Uint8Array;
}

interface PrivateMessageContentApplication extends PrivateMessageContentBase {
    application_data: VarVector;
}

interface PrivateMessageContentProposal extends PrivateMessageContentBase {
    proposal: Proposal;
}

interface PrivateMessageContentCommit extends PrivateMessageContentBase {
    commit: Commit;
}

type PrivateMessageContent = PrivateMessageContentApplication | PrivateMessageContentProposal | PrivateMessageContentCommit;

function IsPrivateMessageContentBase(object: unknown): object is PrivateMessageContentBase {
    return (
        typeof object === "object" &&
        object !== null &&
        "auth" in object &&
        "padding" in object &&
        IsFramedContentAuthData(object.auth) &&
        object.padding instanceof Uint8Array
    );
}

function IsPrivateMessageContentApplication(object: unknown): object is PrivateMessageContentApplication {
    if (!IsPrivateMessageContentBase(object)) {
        return false;
    }
    return (
        "application_data" in object &&
        object.application_data instanceof VarVector &&
        // only 3 fields
        Object.keys(object).length === 3
    );
}

function IsPrivateMessageContentProposal(object: unknown): object is PrivateMessageContentProposal {
    if (!IsPrivateMessageContentBase(object)) {
        return false;
    }
    return (
        "proposal" in object &&
        IsProposal(object.proposal) &&
        // only 3 fields
        Object.keys(object).length === 3
    );
}

function IsPrivateMessageContentCommit(object: unknown): object is PrivateMessageContentCommit {
    if (!IsPrivateMessageContentBase(object)) {
        return false;
    }
    return (
        "commit" in object &&
        IsCommit(object.commit) &&
        // only 3 fields
        Object.keys(object).length === 3
    );
}

function IsPrivateMessageContent(object: unknown): object is PrivateMessageContent {
    return IsPrivateMessageContentApplication(object) || IsPrivateMessageContentProposal(object) || IsPrivateMessageContentCommit(object);
}

export type { PrivateMessageContent };
export { IsPrivateMessageContentApplication, IsPrivateMessageContentProposal, IsPrivateMessageContentCommit, IsPrivateMessageContent };
