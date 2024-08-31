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
     * @param isVarVector Whether to encode the data as a VarVector (when we don't know the length of the data).
     */
    writeUint8Array(data: Uint8Array, isVarVector = true) {
        try {
            if (isVarVector) {
                // encode the data as a VarVector and append it to the fragments
                const vector = VarVector.encode(data);
                this.#fragments.push(vector.buffer);
            } else {
                this.#fragments.push(data.buffer);
            }
        } catch (error) {
            if (error instanceof RangeError) {
                throw new EncodeError("Uint8Array is too large to encode");
            }
            throw error;
        }
        return this;
    }

    writeUint(value: Uint8 | Uint16 | Uint32 | Uint64) {
        const encoded = value.encode();
        this.#fragments.push(encoded.buffer);
        return this;
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
        const { data, offset } = VarVector.decode(this.#data.subarray(this.#offset));
        this.#offset += data.length + offset;
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

    get offset() {
        return this.#offset;
    }
    get data() {
        return this.#data;
    }
}

function IsGREASEValue(value: number) {
    return [0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea].includes(value);
}

export { IsGREASEValue };
