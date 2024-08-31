/**
 * Encodes a variable-length integer according to the format described.
 * @param value - The integer value to encode.
 * @returns A Uint8Array containing the encoded variable-length integer.
 * @throws RangeError if the value is out of range.
 */
function encodeVarintLength(value: number): Uint8Array {
    if (value < 0 || value > 0x3fffffff) {
        throw new RangeError("Value out of range for variable-length integer encoding.");
    }

    if (value <= 63) {
        // Encoding with 1 byte: 00xxxxxx
        const result = new Uint8Array(1);
        result[0] = value & 0x3f; // Masking to fit within 6 bits
        return result;
    } else if (value <= 16383) {
        // Encoding with 2 bytes: 01xxxxxx xxxxxxxx
        const result = new Uint8Array(2);
        result[0] = 0x40 | ((value >> 8) & 0x3f); // 01 in the first two bits
        result[1] = value & 0xff;
        return result;
    } else {
        // Encoding with 4 bytes: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        const result = new Uint8Array(4);
        result[0] = 0x80 | ((value >> 24) & 0x3f); // 10 in the first two bits
        result[1] = (value >> 16) & 0xff;
        result[2] = (value >> 8) & 0xff;
        result[3] = value & 0xff;
        return result;
    }
}

/**
 * Decodes a variable-length integer from a Uint8Array.
 * @param data - The Uint8Array containing the encoded variable-length integer.
 * @returns The decoded integer value.
 * @throws Error if the encoding is invalid.
 */
function decodeVarintLength(data: Uint8Array) {
    let v = data[0];
    let prefix = v >> 6;

    if (prefix === 3) {
        throw new Error("Invalid variable-length integer prefix");
    }

    let length = 1 << prefix;
    v = v & 0x3f;

    for (let i = 1; i < length; i++) {
        v = (v << 8) + data[i];
    }

    // Check for minimum encoding
    if (prefix >= 1 && v < 1 << (8 * (length / 2) - 2)) {
        throw new Error("Minimum encoding was not used");
    }

    return { size: v, offset: length };
}

/**
 * Class to handle variable-size vectors with variable-length integer encoding.
 */
export default class VarVector {
    /**
     * Encodes the vector length and data into a Uint8Array.
     * @param data The Uint8Array to encode.
     * @returns A Uint8Array containing the encoded vector.
     */
    static encode(data: Uint8Array): Uint8Array {
        const length = data.length;
        const lengthBytes = encodeVarintLength(length);
        const result = new Uint8Array(lengthBytes.length + length);
        result.set(lengthBytes, 0);
        result.set(data, lengthBytes.length);
        return result;
    }

    /**
     * Decodes the vector length and retrieves the data.
     * @param data The Uint8Array containing the encoded data.
     * @returns A Uint8Array containing the decoded data.
     */
    static decode(data: Uint8Array) {
        const { size, offset } = decodeVarintLength(data);
        if (size + offset > data.length) {
            throw new Error("Vector length exceeds available data.");
        }
        return { data: data.slice(offset, offset + size), offset };
    }
}

// console.log(encodeVarintLength(494878333), new Uint8Array([0x9d,0x7f,0x3e,0x7d]));
// const original = crypto.getRandomValues(new Uint8Array(100));
// const encoded = VarVector.encode(original);
// const decoded = VarVector.decode(encoded);
// console.log("original:", original);
// console.log("encoded:", encoded);
// console.log("decoded:", decoded);
