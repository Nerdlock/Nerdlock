/**
 * A class representing a 32-bit unsigned integer (uint32).
 */
export default class Uint32 {
    private _value: number | undefined;

    /**
     * Creates an instance of Uint32.
     * @param value - The initial value for the Uint32 instance.
     * @throws If the value is not within the range of a uint32.
     * @throws If the value is not an integer.
     */
    constructor(value = 0) {
        this.value = value; // Use setter to ensure validation
    }

    /**
     * Gets the current value of the Uint32 instance.
     * @returns The value as a 32-bit unsigned integer.
     */
    get value(): number {
        if (this._value === undefined) {
            throw new Error("Value not set");
        }
        return this._value >>> 0;
    }

    /**
     * Sets the value of the Uint32 instance with validation.
     * @param value - The value to set.
     * @throws If the value is not within the range of a uint32.
     * @throws If the value is not an integer.
     */
    set value(value: number) {
        if (typeof value !== "number" || !Number.isInteger(value)) {
            throw new TypeError("Value must be an integer.");
        }
        if (value < 0 || value > 0xffffffff) {
            throw new RangeError("Value must be in the range of a uint32 (0 to 4294967295).");
        }
        this._value = value >>> 0; // Ensure the value is treated as uint32
    }

    /**
     * Adds another Uint32 value to the current value.
     * @param other - The Uint32 instance to add.
     * @returns The current Uint32 instance with updated value.
     * @throws If the operand is not an instance of Uint32.
     */
    add(other: Uint32) {
        if (!(other instanceof Uint32)) {
            throw new TypeError("Operand must be an instance of Uint32.");
        }
        this.value = (this.value + other.value) >>> 0;
        return this;
    }

    /**
     * Subtracts another Uint32 value from the current value.
     * @param other - The Uint32 instance to subtract.
     * @returns The current Uint32 instance with updated value.
     * @throws If the operand is not an instance of Uint32.
     */
    subtract(other: Uint32) {
        if (!(other instanceof Uint32)) {
            throw new TypeError("Operand must be an instance of Uint32.");
        }
        this.value = (this.value - other.value) >>> 0;
        return this;
    }

    /**
     * Performs a bitwise AND with another Uint32 value.
     * @param other - The Uint32 instance to AND with.
     * @returns The current Uint32 instance with updated value.
     * @throws If the operand is not an instance of Uint32.
     */
    and(other: Uint32) {
        if (!(other instanceof Uint32)) {
            throw new TypeError("Operand must be an instance of Uint32.");
        }
        this.value = (this.value & other.value) >>> 0;
        return this;
    }

    /**
     * Performs a bitwise OR with another Uint32 value.
     * @param other - The Uint32 instance to OR with.
     * @returns The current Uint32 instance with updated value.
     * @throws If the operand is not an instance of Uint32.
     */
    or(other: Uint32) {
        if (!(other instanceof Uint32)) {
            throw new TypeError("Operand must be an instance of Uint32.");
        }
        this.value = (this.value | other.value) >>> 0;
        return this;
    }

    /**
     * Performs a bitwise XOR with another Uint32 value.
     * @param other - The Uint32 instance to XOR with.
     * @returns The current Uint32 instance with updated value.
     * @throws If the operand is not an instance of Uint32.
     */
    xor(other: Uint32) {
        if (!(other instanceof Uint32)) {
            throw new TypeError("Operand must be an instance of Uint32.");
        }
        this.value = (this.value ^ other.value) >>> 0;
        return this;
    }

    /**
     * Performs a bitwise NOT operation.
     * @returns The current Uint32 instance with updated value.
     */
    not() {
        this.value = ~this.value >>> 0;
        return this;
    }

    /**
     * Performs a left bitwise shift.
     * @param bits - The number of bits to shift.
     * @returns The current Uint32 instance with updated value.
     * @throws If the number of bits is not an integer.
     */
    leftShift(bits: number) {
        if (typeof bits !== "number" || !Number.isInteger(bits)) {
            throw new TypeError("Bits must be an integer.");
        }
        this.value = (this.value << bits) >>> 0;
        return this;
    }

    /**
     * Performs a right bitwise shift (logical shift).
     * @param bits - The number of bits to shift.
     * @returns The current Uint32 instance with updated value.
     * @throws If the number of bits is not an integer.
     */
    rightShift(bits: number) {
        if (typeof bits !== "number" || !Number.isInteger(bits)) {
            throw new TypeError("Bits must be an integer.");
        }
        this.value = (this.value >>> bits) >>> 0;
        return this;
    }

    /**
     * Converts the value to a hexadecimal string.
     * @returns The value as a hexadecimal string.
     */
    toHexString() {
        return `0x${this.value.toString(16).padStart(8, "0")}`;
    }

    /**
     * Converts the value to a string in base 10.
     * @returns The value as a base 10 string.
     */
    toString() {
        return this.value.toString(10);
    }

    /**
     * Encode this Uint32 value as a 4-byte Uint8Array.
     * @returns The value encoded as a 4-byte Uint8Array.
     */
    encode() {
        const buffer = new Uint8Array(4);
        buffer[0] = (this.value >> 24) & 0xff;
        buffer[1] = (this.value >> 16) & 0xff;
        buffer[2] = (this.value >> 8) & 0xff;
        buffer[3] = this.value & 0xff;
        return buffer;
    }

    /**
     * Decode a 4-byte Uint8Array into a Uint32 value.
     * @param buffer The buffer to decode.
     * @returns The decoded Uint32 value.
     */
    static decode(buffer: Uint8Array) {
        if (buffer.length !== 4) {
            throw new Error("Invalid buffer length");
        }
        const value = (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
        return new Uint32(value >>> 0);
    }

    static from(value: number) {
        return new Uint32(value & 0xffffffff);
    }
}
