import { CipherSuite } from "@hpke/core";
import Uint64 from "./types/Uint64";
import { Decoder, Encoder } from "./Encoding";
import Uint16 from "./types/Uint16";
import MalformedObjectError from "./errors/MalformedObjectError";
import { CipherSuiteType, ExtensionType, ProtocolVersion } from "./Enums";
import { EncodeExtension, IsExtension, type Extension } from "./Extension";

interface GroupContext {
    version: ProtocolVersion.mls10;
    cipher_suite: CipherSuiteType;
    group_id: Uint8Array;
    epoch: Uint64;
    tree_hash: Uint8Array;
    confirmed_transcript_hash: Uint8Array;
    extensions: Extension<ExtensionType.required_capabilities | ExtensionType.external_senders>[];
}

function IsGroupContext(object: unknown): object is GroupContext {
    return (
        typeof object === "object" &&
        object !== null &&
        "version" in object &&
        "cipher_suite" in object &&
        "group_id" in object &&
        "epoch" in object &&
        "tree_hash" in object &&
        "confirmed_transcript_hash" in object &&
        "extensions" in object &&
        object.version === ProtocolVersion.mls10 &&
        object.cipher_suite instanceof CipherSuite &&
        object.group_id instanceof Uint8Array &&
        object.epoch instanceof Uint64 &&
        object.tree_hash instanceof Uint8Array &&
        object.confirmed_transcript_hash instanceof Uint8Array &&
        object.extensions instanceof Array &&
        object.extensions.every((e) => IsExtension(e, ExtensionType.required_capabilities) || IsExtension(e, ExtensionType.external_senders))
    );
}

function EncodeGroupContext(context: GroupContext) {
    const encoder = new Encoder();
    encoder.writeUint(Uint16.from(ProtocolVersion.mls10));
    encoder.writeUint(Uint16.from(context.cipher_suite));
    encoder.writeUint8Array(context.group_id);
    encoder.writeUint(context.epoch);
    encoder.writeUint8Array(context.tree_hash);
    encoder.writeUint8Array(context.confirmed_transcript_hash);
    encoder.writeUint(Uint16.from(context.extensions.length));
    context.extensions.forEach((e) => encoder.writeUint8Array(EncodeExtension(e), false));
    return encoder.flush();
}

function DecodeGroupContext(decoder: Decoder) {
    const context = {
        version: decoder.readUint16(),
        cipher_suite: decoder.readUint16(),
        group_id: decoder.readUint8Array(),
        epoch: decoder.readUint64(),
        tree_hash: decoder.readUint8Array(),
        confirmed_transcript_hash: decoder.readUint8Array(),
        extensions: undefined
    }
    if (!IsGroupContext(context)) {
        throw new MalformedObjectError("Invalid group context", "context", context);
    }
    return context;
}

export type { GroupContext };
export { IsGroupContext, EncodeGroupContext, DecodeGroupContext };