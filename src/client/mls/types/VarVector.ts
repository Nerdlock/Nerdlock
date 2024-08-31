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

    let bytes: number[] = [];
    let prefix: number;

    if (value < 64) {
        prefix = 0;
        bytes.push(value);
    } else if (value < 16384) {
        prefix = 1;
        bytes.push((value & 0x3f) | 0x40);
        bytes.push((value >> 6) & 0xff);
    } else if (value < 1073741824) {
        prefix = 2;
        bytes.push((value & 0x3f) | 0x80);
        bytes.push((value >> 6) & 0xff);
        bytes.push((value >> 14) & 0xff);
        bytes.push((value >> 22) & 0xff);
    } else {
        throw new RangeError("Value out of range for variable-length integer encoding.");
    }

    bytes[0] |= prefix << 6;
    return new Uint8Array(bytes);
}

/**
 * Decodes a variable-length integer from a Uint8Array.
 * @param data - The Uint8Array containing the encoded variable-length integer.
 * @returns The decoded integer value.
 * @throws Error if the encoding is invalid.
 */
function decodeVarintLength(data: Uint8Array): number {
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

    return v;
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
        const length = decodeVarintLength(data);
        if (length + 1 > data.length) {
            throw new Error("Vector length exceeds available data.");
        }
        return data.slice(1, length + 1);
    }
}
