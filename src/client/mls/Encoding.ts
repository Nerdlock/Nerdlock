import Uint8 from "./types/Uint8";
import Uint16 from "./types/Uint16";
import Uint32 from "./types/Uint32";
import Uint64 from "./types/Uint64";
import VarVector from "./types/VarVector";
import DecodeError from "./errors/DecodeError";
import EncodeError from "./errors/EncodeError";

/**
 * An encoder class used to encode various data types into a byte array.
 */
export class Encoder {
    #fragments = new Array<ArrayBufferLike>();

    /**
     * Flush the encoder and return the encoded data as a byte array.
     * @returns The encoded data as a Uint8Array.
     */
    flush() {
        const buffer = new Uint8Array(this.#fragments.reduce((acc, cur) => acc + cur.byteLength, 0));
        let offset = 0;
        for (const fragment of this.#fragments) {
            buffer.set(new Uint8Array(fragment), offset);
            offset += fragment.byteLength;
        }
        this.#fragments.length = 0;
        return buffer;
    }

    /**
     * Write a Uint8Array as a VarVector.
     * @param data The Uint8Array to encode.
     */
    writeUint8Array(data: Uint8Array) {
        try {
            
            // encode the data as a VarVector and append it to the fragments
            const vector = VarVector.encode(data);
            this.#fragments.push(vector.buffer);
        } catch(error) {
            if(error instanceof RangeError) {
                throw new EncodeError("Uint8Array is too large to encode");
            }
            throw error;
        }
    }

    writeUint8(value: Uint8) {
        // call the Uint8.encode method to get the encoded value
        const encoded = value.encode();
        this.#fragments.push(encoded.buffer);
    }

    writeUint16(value: Uint16) {
        // call the Uint16.encode method to get the encoded value
        const encoded = value.encode();
        this.#fragments.push(encoded.buffer);
    }

    writeUint32(value: Uint32) {
        // call the Uint32.encode method to get the encoded value
        const encoded = value.encode();
        this.#fragments.push(encoded.buffer);
    }

    writeUint64(value: Uint64) {
        // call the Uint64.encode method to get the encoded value
        const encoded = value.encode();
        this.#fragments.push(encoded.buffer);
    }
}

export class Decoder {
    #data: Uint8Array;
    #offset: number;

    constructor(data: Uint8Array) {
        this.#data = data;
        this.#offset = 0;
    }

    readUint8Array() {
        const data = VarVector.decode(this.#data.subarray(this.#offset));
        // offset by the length + 1 (the varvec length)
        this.#offset += data.length + 1;
        return data;
    }

    readUint8() {
        // check if we have enough data to read a Uint8
        if (this.#offset + 1 > this.#data.length) {
            throw new DecodeError("Not enough data to read a Uint8");
        }
        const value = Uint8.decode(this.#data.subarray(this.#offset, this.#offset + 1));
        this.#offset += 1;
        return value;
    }

    readUint16() {
        if (this.#offset + 2 > this.#data.length) {
            throw new DecodeError("Not enough data to read a Uint16");
        }
        const value = Uint16.decode(this.#data.subarray(this.#offset, this.#offset + 2));
        this.#offset += 2;
        return value;
    }

    readUint32() {
        if (this.#offset + 4 > this.#data.length) {
            throw new DecodeError("Not enough data to read a Uint32");
        }
        const value = Uint32.decode(this.#data.subarray(this.#offset, this.#offset + 4));
        this.#offset += 4;
        return value;
    }

    readUint64() {
        if (this.#offset + 8 > this.#data.length) {
            throw new DecodeError("Not enough data to read a Uint64");
        }
        const value = Uint64.decode(this.#data.subarray(this.#offset, this.#offset + 8));
        this.#offset += 8;
        return value;
    }
}

function IsGREASEValue(value: number) {
    return [0x1A1A,0x2A2A,0x3A3A,0x4A4A,0x5A5A,0x6A6A,0x7A7A,0x8A8A,0x9A9A,0xAAAA,0xBABA,0xCACA,0xDADA,0xEAEA].includes(value);
}

export { IsGREASEValue };