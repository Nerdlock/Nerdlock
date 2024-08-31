/**
 * A class representing a 64-bit unsigned integer (uint64).
 */
export default class Uint64 {
    private high: number;
    private low: number;

    /**
     * Creates an instance of Uint64.
     * @param {number} high - The high 32 bits of the 64-bit unsigned integer.
     * @param {number} low - The low 32 bits of the 64-bit unsigned integer.
     */
    constructor(high = 0, low = 0) {
        this.high = high >>> 0; // Ensure high is treated as uint32
        this.low = low >>> 0; // Ensure low is treated as uint32
    }

    /**
     * Gets the value as a 64-bit unsigned integer.
     * @returns {BigInt} The value as a BigInt.
     */
    get value(): bigint {
        return (BigInt(this.high) << BigInt(32)) | BigInt(this.low);
    }

    /**
     * Sets the value from a BigInt.
     * @param {BigInt} value - The BigInt value to set.
     */
    set value(value: bigint) {
        if (value < 0 || value > BigInt(0xffffffffffffffffn)) {
            throw new RangeError("Value must be in the range of a uint64 (0 to 18446744073709551615).");
        }
        this.high = Number(value >> BigInt(32)) >>> 0; // High 32 bits
        this.low = Number(value & BigInt(0xffffffff)) >>> 0; // Low 32 bits
    }

    /**
     * Adds another Uint64 value to the current value.
     * @param {Uint64} other - The Uint64 instance to add.
     * @returns {Uint64} The current Uint64 instance with updated value.
     * @throws {TypeError} If the operand is not an instance of Uint64.
     */
    add(other: Uint64) {
        if (!(other instanceof Uint64)) {
            throw new TypeError("Operand must be an instance of Uint64.");
        }
        const lowSum = (this.low + other.low) >>> 0;
        const highSum = (this.high + other.high + ((this.low + other.low) >>> 32)) >>> 0;
        this.high = highSum;
        this.low = lowSum;
        return this;
    }

    /**
     * Subtracts another Uint64 value from the current value.
     * @param {Uint64} other - The Uint64 instance to subtract.
     * @returns {Uint64} The current Uint64 instance with updated value.
     * @throws {TypeError} If the operand is not an instance of Uint64.
     */
    subtract(other: Uint64) {
        if (!(other instanceof Uint64)) {
            throw new TypeError("Operand must be an instance of Uint64.");
        }
        const lowDiff = (this.low - other.low) >>> 0;
        const highDiff = (this.high - other.high - (this.low < other.low ? 1 : 0)) >>> 0;
        this.high = highDiff;
        this.low = lowDiff;
        return this;
    }

    /**
     * Performs a bitwise AND with another Uint64 value.
     * @param {Uint64} other - The Uint64 instance to AND with.
     * @returns {Uint64} The current Uint64 instance with updated value.
     * @throws {TypeError} If the operand is not an instance of Uint64.
     */
    and(other: Uint64) {
        if (!(other instanceof Uint64)) {
            throw new TypeError("Operand must be an instance of Uint64.");
        }
        this.high = this.high & other.high;
        this.low = this.low & other.low;
        return this;
    }

    /**
     * Performs a bitwise OR with another Uint64 value.
     * @param {Uint64} other - The Uint64 instance to OR with.
     * @returns {Uint64} The current Uint64 instance with updated value.
     * @throws {TypeError} If the operand is not an instance of Uint64.
     */
    or(other: Uint64) {
        if (!(other instanceof Uint64)) {
            throw new TypeError("Operand must be an instance of Uint64.");
        }
        this.high = this.high | other.high;
        this.low = this.low | other.low;
        return this;
    }

    /**
     * Performs a bitwise XOR with another Uint64 value.
     * @param {Uint64} other - The Uint64 instance to XOR with.
     * @returns {Uint64} The current Uint64 instance with updated value.
     * @throws {TypeError} If the operand is not an instance of Uint64.
     */
    xor(other: Uint64) {
        if (!(other instanceof Uint64)) {
            throw new TypeError("Operand must be an instance of Uint64.");
        }
        this.high = this.high ^ other.high;
        this.low = this.low ^ other.low;
        return this;
    }

    /**
     * Performs a bitwise NOT operation.
     * @returns {Uint64} The current Uint64 instance with updated value.
     */
    not() {
        this.high = ~this.high >>> 0;
        this.low = ~this.low >>> 0;
        return this;
    }

    /**
     * Performs a left bitwise shift.
     * @param {number} bits - The number of bits to shift.
     * @returns {Uint64} The current Uint64 instance with updated value.
     * @throws {TypeError} If the number of bits is not an integer.
     */
    leftShift(bits: number) {
        if (typeof bits !== "number" || !Number.isInteger(bits)) {
            throw new TypeError("Bits must be an integer.");
        }
        if (bits >= 64) {
            this.high = 0;
            this.low = 0;
        } else if (bits >= 32) {
            this.high = (this.low << (bits - 32)) >>> 0;
            this.low = 0;
        } else {
            this.high = ((this.high << bits) | (this.low >>> (32 - bits))) >>> 0;
            this.low = (this.low << bits) >>> 0;
        }
        return this;
    }

    /**
     * Performs a right bitwise shift (logical shift).
     * @param {number} bits - The number of bits to shift.
     * @returns {Uint64} The current Uint64 instance with updated value.
     * @throws {TypeError} If the number of bits is not an integer.
     */
    rightShift(bits: number) {
        if (typeof bits !== "number" || !Number.isInteger(bits)) {
            throw new TypeError("Bits must be an integer.");
        }
        if (bits >= 64) {
            this.high = 0;
            this.low = 0;
        } else if (bits >= 32) {
            this.low = (this.high >>> (bits - 32)) >>> 0;
            this.high = 0;
        } else {
            this.low = ((this.low >>> bits) | (this.high << (32 - bits))) >>> 0;
            this.high = this.high >>> bits;
        }
        return this;
    }

    /**
     * Converts the value to a hex string.
     * @returns {string} The value as a hexadecimal string.
     */
    toHexString(): string {
        return `0x${this.high.toString(16).padStart(8, "0")}${this.low.toString(16).padStart(8, "0")}`;
    }

    /**
     * Converts the value to a string (base 10).
     * @returns {string} The value as a base 10 string.
     */
    toString(): string {
        return this.value.toString();
    }

    /**
     * Encode this Uint64 value as an 8-byte Uint8Array.
     * @returns The value encoded as an 8-byte Uint8Array.
     */
    encode() {
        const buffer = new Uint8Array(8);
        buffer[0] = (this.high >>> 24) & 0xff;
        buffer[1] = (this.high >>> 16) & 0xff;
        buffer[2] = (this.high >>> 8) & 0xff;
        buffer[3] = this.high & 0xff;
        buffer[4] = (this.low >>> 24) & 0xff;
        buffer[5] = (this.low >>> 16) & 0xff;
        buffer[6] = (this.low >>> 8) & 0xff;
        buffer[7] = this.low & 0xff;
        return buffer;
    }

    /**
     * Decode an 8-byte Uint8Array into a Uint64 value.
     * @param buffer The buffer to decode.
     * @returns The decoded Uint64 value.
     */
    static decode(buffer: Uint8Array) {
        if (buffer.length !== 8) {
            throw new Error("Uint8Array must be 8 bytes long");
        }
        const high = (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
        const low = (buffer[4] << 24) | (buffer[5] << 16) | (buffer[6] << 8) | buffer[7];
        return new Uint64(high >>> 0, low >>> 0); // Treat as unsigned
    }

    static from(value: bigint) {
        return new Uint64(Number(value >> BigInt(32)) >>> 0, Number(value & BigInt(0xffffffff)) >>> 0);
    }
}
