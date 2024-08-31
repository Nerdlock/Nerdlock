import { concatBytes } from "@noble/hashes/utils";
import { DeriveSecret, Hash } from "./CryptoHelper";
import type { CipherSuiteType } from "./Enums";

type EpochSecretType = "sender_data_secret" | "encryption_secret" | "exporter_secret" | "external_secret" | "confirmation_key" | "membership_key" | "resumption_psk" | "epoch_authenticator";

/**
 * A class for managing the key schedule of epoches.
 */
export default class KeySchedule {
    #epochSecret: Uint8Array | undefined;
    #cipherSuite: CipherSuiteType;
    #secrets: Record<EpochSecretType, Uint8Array | undefined>;
    #interim_transcript_hash: Uint8Array | undefined;

    constructor(secret: Uint8Array, cipherSuite: CipherSuiteType) {
        this.#epochSecret = secret;
        this.#cipherSuite = cipherSuite;
        this.#secrets = {
            sender_data_secret: undefined,
            encryption_secret: undefined,
            exporter_secret: undefined,
            external_secret: undefined,
            confirmation_key: undefined,
            membership_key: undefined,
            resumption_psk: undefined,
            epoch_authenticator: undefined,
        }
    }

    async #computeEpochSecret() {
        if(this.#epochSecret == null) {
            throw new Error("Epoch secret not set");
        }
        const encoder = new TextEncoder();
        await Promise.all([
            DeriveSecret(this.#epochSecret, encoder.encode("sender data"), this.#cipherSuite),
            DeriveSecret(this.#epochSecret, encoder.encode("encryption"), this.#cipherSuite),
            DeriveSecret(this.#epochSecret, encoder.encode("exporter"), this.#cipherSuite),
            DeriveSecret(this.#epochSecret, encoder.encode("external"), this.#cipherSuite),
            DeriveSecret(this.#epochSecret, encoder.encode("confirm"), this.#cipherSuite),
            DeriveSecret(this.#epochSecret, encoder.encode("membership"), this.#cipherSuite),
            DeriveSecret(this.#epochSecret, encoder.encode("resumption"), this.#cipherSuite),
            DeriveSecret(this.#epochSecret, encoder.encode("authentication"), this.#cipherSuite),
        ]).then(secrets => {
            this.#secrets = {
                sender_data_secret: secrets[0],
                encryption_secret: secrets[1],
                exporter_secret: secrets[2],
                external_secret: secrets[3],
                confirmation_key: secrets[4],
                membership_key: secrets[5],
                resumption_psk: secrets[6],
                epoch_authenticator: secrets[7],
            }
        });
        // delete the epoch secret
        this.#epochSecret = undefined;
    }

    getSecret(type: EpochSecretType) {
        return this.#secrets[type];
    }

    static async fromEpochSecret(secret: Uint8Array, cipherSuite: CipherSuiteType) {
        const schedule = new KeySchedule(secret, cipherSuite);
        await schedule.#computeEpochSecret();
        return schedule;
    }

    async computeInterimTranscriptHash(confirmed_transcript_hash: Uint8Array, confirmation_tag: Uint8Array) {
        this.#interim_transcript_hash = await(Hash(concatBytes(confirmed_transcript_hash, confirmation_tag), this.#cipherSuite));
    }

    get interim_transcript_hash() {
        return this.#interim_transcript_hash;
    }
}