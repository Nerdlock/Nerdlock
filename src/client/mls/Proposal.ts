import type { ProposalType } from "./Enums";
import type { KeyPackage } from "./messages/KeyPackage";



interface ProposalBase {
    proposal_type: ProposalType
}

interface ProposalAdd extends ProposalBase {
    proposal_type: ProposalType.add;
    key_package: KeyPackage;
}

export type { Proposal };
