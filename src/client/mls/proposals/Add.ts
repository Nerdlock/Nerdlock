import { Decoder } from "../Encoding";
import { ProposalType } from "../Enums";
import InvalidObjectError from "../errors/InvalidObjectError";
import { DecodeKeyPackage, IsKeyPackage, type KeyPackage } from "../messages/KeyPackage";
import { IsProposalBase, type ProposalBase } from "../Proposal";

interface AddProposal extends ProposalBase {
    proposal_type: ProposalType.add;
    key_package: KeyPackage;
}

function IsAddProposal(object: unknown): object is AddProposal {
    if (!IsProposalBase(object)) {
        return false;
    }
    return (
        object.proposal_type === ProposalType.add &&
        "key_package" in object &&
        IsKeyPackage(object.key_package)
    );
}

function DecodeAddProposal(base: ProposalBase, decoder: Decoder): AddProposal {
    const key_package = DecodeKeyPackage(decoder);
    const proposal = {
        proposal_type: base.proposal_type,
        key_package
    }
    if(!IsAddProposal(proposal)) {
        throw new InvalidObjectError("Invalid add proposal");
    }
    return proposal;
}

export { DecodeAddProposal, IsAddProposal };
export type { AddProposal };
