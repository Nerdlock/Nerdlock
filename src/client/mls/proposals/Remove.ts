import type { Decoder } from "../Encoding";
import { ProposalType } from "../Enums";
import InvalidObjectError from "../errors/InvalidObjectError";
import { IsProposalBase, type ProposalBase } from "../Proposal";
import Uint32 from "../types/Uint32";

interface RemoveProposal extends ProposalBase {
    proposal_type: ProposalType.remove;
    removed: Uint32;
}

function IsRemoveProposal(object: unknown): object is RemoveProposal {
    if (!IsProposalBase(object)) {
        return false;
    }
    return object.proposal_type === ProposalType.remove && "removed" in object && object.removed instanceof Uint32;
}

function DecodeRemoveProposal(base: ProposalBase, decoder: Decoder): RemoveProposal {
    const removed = decoder.readUint32();
    const proposal = {
        proposal_type: base.proposal_type,
        removed
    };
    if (!IsRemoveProposal(proposal)) {
        throw new InvalidObjectError("Invalid remove proposal");
    }
    return proposal;
}

export type { RemoveProposal };
export { IsRemoveProposal, DecodeRemoveProposal };
