import type { Decoder } from "../Encoding";
import { ProposalType } from "../Enums";
import InvalidObjectError from "../errors/InvalidObjectError";
import { IsProposalBase, type ProposalBase } from "../Proposal";
import { DecodeLeafNode, type LeafNode } from "../RatchetTree";

interface UpdateProposal extends ProposalBase {
    proposal_type: ProposalType.update;
    leaf_node: LeafNode;
}

function IsUpdateProposal(object: unknown): object is UpdateProposal {
    if (!IsProposalBase(object)) {
        return false;
    }
    return (
        object.proposal_type === ProposalType.update &&
        "leaf_node" in object &&
        object.leaf_node !== null
    );
}

function DecodeUpdateProposal(base: ProposalBase, decoder: Decoder): UpdateProposal {
    const leaf_node = DecodeLeafNode(decoder);
    const proposal = {
        proposal_type: base.proposal_type,
        leaf_node
    }
    if(!IsUpdateProposal(proposal)) {
        throw new InvalidObjectError("Invalid update proposal");
    }
    return proposal;
}

export type { UpdateProposal };
export { IsUpdateProposal, DecodeUpdateProposal };