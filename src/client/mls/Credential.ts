import { Decoder, Encoder } from "./Encoding";
import { CredentialType } from "./Enums";
import MalformedObjectError from "./errors/MalformedObjectError";
import Uint16 from "./types/Uint16";

interface Certificate {
    cert_data: Uint8Array;
}

interface CredentialBase {
    credential_type: CredentialType;
}

interface CredentialBasic {
    credential_type: CredentialType.basic;
    identity: Uint8Array;
}

interface CredentialX509 {
    credential_type: CredentialType.x509;
    credentials: Certificate[];
}

type Credential = CredentialBasic | CredentialX509;

function IsCertificate(object: unknown): object is Certificate {
    return (
        typeof object === "object" &&
        object !== null &&
        "cert_data" in object &&
        object.cert_data instanceof Uint8Array
    );
}

function IsCredentialBase(object: unknown): object is CredentialBase {
    return (
        typeof object === "object" &&
        object !== null &&
        "credential_type" in object &&
        typeof object.credential_type === "number"
    );
}

function IsCredentialBasic(object: unknown): object is CredentialBasic {
    if (!IsCredentialBase(object)) {
        return false;
    }
    // credential_type is CredentialType.basic
    return (
        object.credential_type === CredentialType.basic &&
        "identity" in object &&
        object.identity instanceof Uint8Array
    );
}

function IsCredentialX509(object: unknown): object is CredentialX509 {
    if (!IsCredentialBase(object)) {
        return false;
    }
    // credential_type is CredentialType.x509
    return (
        object.credential_type === CredentialType.x509 &&
        "credentials" in object &&
        Array.isArray(object.credentials) &&
        object.credentials.every((c) => IsCertificate(c))
    );
}

function IsCredential(object: unknown): object is Certificate {
    return IsCredentialBasic(object) || IsCredentialX509(object);
}

function EncodeCredential(credential: Credential) {
    const encoder = new Encoder();
    encoder.writeUint(Uint16.from(credential.credential_type));
    if (IsCredentialBasic(credential)) {
        encoder.writeUint8Array(credential.identity);
    }
    if (IsCredentialX509(credential)) {
        encoder.writeArray(credential.credentials, (c, encoder) => encoder.writeUint8Array(c.cert_data));
    }
    return encoder.flush();
}

function DecodeCredential(decoder: Decoder): Credential {
    const credential_type = decoder.readUint16().value;
    if (credential_type === CredentialType.basic) {
        return {
            credential_type: credential_type,
            identity: decoder.readUint8Array()
        } satisfies CredentialBasic;
    } else if (credential_type === CredentialType.x509) {
        const credentials = decoder.readArray((decoder) => {
            return {
                cert_data: decoder.readUint8Array()
            } satisfies Certificate;
        });
        return {
            credential_type: credential_type,
            credentials: credentials
        } satisfies CredentialX509;
    } else {
        throw new MalformedObjectError("Invalid credential type", "credential_type", credential_type);
    }
}

export { DecodeCredential, EncodeCredential, IsCredential, IsCredentialBasic, IsCredentialX509 };
export type { Credential, CredentialBasic, CredentialX509 };

