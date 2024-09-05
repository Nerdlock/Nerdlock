export type OmitMultiple<T, K extends Array<keyof T>> = Omit<T, K[number]>;
// declare CryptoKeyPair in the global namespace
declare global {
    interface CryptoKeyPair {
        privateKey: CryptoKey;
        publicKey: CryptoKey;
    }
}