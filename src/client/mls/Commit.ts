import type { ProposalOrRefType } from "./Enums";
import type { Proposal } from "./Proposal";

interface ProposalOrRefBase {
    type: ProposalOrRefType;
}

interface ProposalOrRefProposal extends ProposalOrRefBase {
    type: ProposalOrRefType.proposal;
    proposal: Proposal;
}

interface ProposalOrRefReference extends ProposalOrRefBase {
    type: ProposalOrRefType.reference;
    reference: Uint32;
}


type Commit = {}

export type { Commit };