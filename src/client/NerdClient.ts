import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { edwardsToMontgomeryPriv, edwardsToMontgomeryPub } from "@noble/curves/ed25519";
import * as ed from "@noble/ed25519";
import "./mls/Group";
/**
 * Entrypoint for the NerdLock client using MLS as the underlying protocol.
 */
const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm()
});
const pk = ed.utils.randomPrivateKey();
const edwardskp = {
    privateKey: pk,
    publicKey: await ed.getPublicKeyAsync(pk)
};
const montgomerykp = {
    privateKey: edwardsToMontgomeryPriv(edwardskp.privateKey),
    publicKey: edwardsToMontgomeryPub(edwardskp.publicKey)
};
const skp = {
    privateKey: await suite.kem.deserializePrivateKey(montgomerykp.privateKey.slice(0, suite.kem.privateKeySize).buffer as ArrayBuffer),
    publicKey: await suite.kem.deserializePublicKey(montgomerykp.publicKey.slice(0, suite.kem.publicKeySize).buffer as ArrayBuffer)
};
console.log(skp);
const rkp = await suite.kem.generateKeyPair();
const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
    senderKey: skp.privateKey
});
const ct = await sender.seal(new TextEncoder().encode("Hello, world!").buffer as ArrayBuffer);
const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc,
    senderPublicKey: skp.publicKey
});

const pt = await recipient.open(ct);
console.log(new TextDecoder().decode(pt));

const message = Uint8Array.from([0xde, 0xad, 0xbe, 0xef]);
const signature = await ed.signAsync(message, edwardskp.privateKey);
console.log(signature);
console.log(edwardskp);
console.log(await ed.verifyAsync(signature, message, edwardskp.publicKey));
