import { Decoder, Encoder } from "./Encoding";
import { ExtensionType, type CredentialType, type ProposalType } from "./Enums";
import MalformedObjectError from "./errors/MalformedObjectError";
import Uint16 from "./types/Uint16";

interface Extension<T extends ExtensionType> {
    extension_type: T;
    extension_data: ExtensionData<T>;
}

interface RequiredCapabilities {
    extension_types: ExtensionType[];
    proposal_types: ProposalType[];
    credential_types: CredentialType[];
}

function IsRequiredCapabilities(object: unknown): object is RequiredCapabilities {
    return (
        typeof object === "object" &&
        object !== null &&
        "extension_types" in object &&
        object.extension_types instanceof Array &&
        object.extension_types.every((v) => typeof v === "number") &&
        "proposal_types" in object &&
        object.proposal_types instanceof Array &&
        object.proposal_types.every((v) => typeof v === "number") &&
        "credential_types" in object &&
        object.credential_types instanceof Array &&
        object.credential_types.every((v) => typeof v === "number")
    );
}

type ExtensionData<T extends ExtensionType> = T extends ExtensionType.required_capabilities ? RequiredCapabilities : never;

function IsExtensionData<T extends ExtensionType>(object: unknown, extensionType: T): object is ExtensionData<T> {
    const validData = typeof object === "object" && object !== null;
    if (!validData) {
        return false;
    }
    if (IsRequiredCapabilities(object) && extensionType === ExtensionType.required_capabilities) {
        return true;
    }
    return false;
}

function IsExtension<T extends ExtensionType>(object: unknown, extensionType: T): object is Extension<T> {
    const validObject = (
        typeof object === "object" &&
        object !== null &&
        "extension_type" in object &&
        typeof object.extension_type === "number" &&
        "extension_data" in object &&
        typeof object.extension_data === "object" &&
        object.extension_data !== null
    );
    if (!validObject) {
        return false;
    }
    if (IsRequiredCapabilities(object.extension_data) && extensionType === ExtensionType.required_capabilities) {
        return true;
    }
    return false;
}

function EncodeExtension(extension: Extension<ExtensionType>) {
    const encoder = new Encoder();
    encoder.writeUint(Uint16.from(extension.extension_type));
    if (IsExtensionData(extension.extension_data, ExtensionType.required_capabilities)) {
        const extension_typesLength = extension.extension_data.extension_types.length;
        encoder.writeUint(Uint16.from(extension_typesLength));
        extension.extension_data.extension_types.forEach((v) => encoder.writeUint(Uint16.from(v)));
        const proposal_typesLength = extension.extension_data.proposal_types.length;
        encoder.writeUint(Uint16.from(proposal_typesLength));
        extension.extension_data.proposal_types.forEach((v) => encoder.writeUint(Uint16.from(v)));
        const credential_typesLength = extension.extension_data.credential_types.length;
        encoder.writeUint(Uint16.from(credential_typesLength));
        extension.extension_data.credential_types.forEach((v) => encoder.writeUint(Uint16.from(v)));
    }
    return encoder.flush();
}

function DecodeExtension(decoder: Decoder): Extension<ExtensionType> {
    const extension_type = decoder.readUint16().value;
    if (extension_type === ExtensionType.required_capabilities) {
        const extension_typesLength = decoder.readUint16().value;
        const extension_types: ExtensionType[] = [];
        for (let i = 0; i < extension_typesLength; i++) {
            const extension_type = decoder.readUint16().value;
            extension_types.push(extension_type);
        }
        const proposal_typesLength = decoder.readUint16().value;
        const proposal_types: ProposalType[] = [];
        for (let i = 0; i < proposal_typesLength; i++) {
            const proposal_type = decoder.readUint16().value;
            proposal_types.push(proposal_type);
        }
        const credential_typesLength = decoder.readUint16().value;
        const credential_types: CredentialType[] = [];
        for (let i = 0; i < credential_typesLength; i++) {
            const credential_type = decoder.readUint16().value;
            credential_types.push(credential_type);
        }
        return {
            extension_type,
            extension_data: {
                extension_types,
                proposal_types,
                credential_types
            }
        } satisfies Extension<ExtensionType.required_capabilities>;
    }
    throw new MalformedObjectError("Invalid extension type", "extension_type", extension_type);
}

export type { Extension };
export { IsExtension, EncodeExtension, DecodeExtension };