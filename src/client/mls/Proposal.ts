import { Decoder, Encoder } from "./Encoding";
import { ProposalType } from "./Enums";
import InvalidObjectError from "./errors/InvalidObjectError";
import { EncodeKeyPackage } from "./messages/KeyPackage";
import { DecodeAddProposal, IsAddProposal, type AddProposal } from "./proposals/Add";
import { DecodeRemoveProposal, IsRemoveProposal, type RemoveProposal } from "./proposals/Remove";
import { DecodeUpdateProposal, IsUpdateProposal, type UpdateProposal } from "./proposals/Update";
import { EncodeLeafNode } from "./RatchetTree";
import Uint16 from "./types/Uint16";

interface ProposalBase {
    proposal_type: ProposalType
}

function IsProposalBase(object: unknown): object is ProposalBase {
    return (
        typeof object === "object" &&
        object !== null &&
        "proposal_type" in object &&
        typeof object.proposal_type === "number"
    );
}

type Proposal = AddProposal | UpdateProposal | RemoveProposal;

function EncodeProposal(proposal: Proposal) {
    const encoder = new Encoder();
    encoder.writeUint(Uint16.from(proposal.proposal_type));
    switch (proposal.proposal_type) {
        case ProposalType.add:
            encoder.writeUint8Array(EncodeKeyPackage(proposal.key_package), false);
            break;
        case ProposalType.update:
            encoder.writeUint8Array(EncodeLeafNode(proposal.leaf_node), false);
            break
        case ProposalType.remove:
            encoder.writeUint(proposal.removed);
            break;
        default:
            throw new InvalidObjectError("Invalid proposal type");
    }
    return encoder.flush();
}

function DecodeProposal(decoder: Decoder) {
    const proposal_type = decoder.readUint16().value;
    const base = {
        proposal_type
    } satisfies ProposalBase;
    switch (proposal_type) {
        case ProposalType.add:
            return DecodeAddProposal(base, decoder);
        case ProposalType.update:
            return DecodeUpdateProposal(base, decoder);
        case ProposalType.remove:
            return DecodeRemoveProposal(base, decoder);
        default:
            throw new InvalidObjectError("Invalid proposal type");
    }
}

function IsProposal(object: unknown): object is Proposal {
    return IsAddProposal(object) || IsUpdateProposal(object) || IsRemoveProposal(object);
}

export type { Proposal, ProposalBase };
export { IsProposalBase, EncodeProposal, DecodeProposal, IsProposal };
