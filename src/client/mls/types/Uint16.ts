/**
 * A class representing a 16-bit unsigned integer (uint16).
 */
export default class Uint16 {
    private _value: number | undefined;

    /**
     * Creates an instance of Uint16.
     * @param value - The initial value for the Uint16 instance.
     * @throws If the value is not within the range of a uint16.
     * @throws If the value is not an integer.
     */
    constructor(value = 0) {
        this.value = value; // Use setter to ensure validation
    }

    /**
     * Gets the current value of the Uint16 instance.
     * @returns The value as a 16-bit unsigned integer.
     */
    get value(): number {
        if (this._value === undefined) {
            throw new Error("Value not set");
        }
        return this._value & 0xffff;
    }

    /**
     * Sets the value of the Uint16 instance with validation.
     * @param value - The value to set.
     * @throws If the value is not within the range of a uint16.
     * @throws If the value is not an integer.
     */
    set value(value: number) {
        if (typeof value !== "number" || !Number.isInteger(value)) {
            throw new TypeError("Value must be an integer.");
        }
        if (value < 0 || value > 0xffff) {
            throw new RangeError("Value must be in the range of a uint16 (0 to 65535).");
        }
        this._value = value & 0xffff; // Ensure the value is treated as uint16
    }

    // Methods for addition, subtraction, bitwise operations, shifting, and encoding/decoding
    // are the same as in the Uint32 class, but adjusted for 16-bit operations.
    add(other: Uint16) {
        if (!(other instanceof Uint16)) {
            throw new TypeError("Operand must be an instance of Uint16.");
        }
        this.value = (this.value + other.value) & 0xffff;
        return this;
    }

    subtract(other: Uint16) {
        if (!(other instanceof Uint16)) {
            throw new TypeError("Operand must be an instance of Uint16.");
        }
        this.value = (this.value - other.value) & 0xffff;
        return this;
    }

    and(other: Uint16) {
        if (!(other instanceof Uint16)) {
            throw new TypeError("Operand must be an instance of Uint16.");
        }
        this.value = (this.value & other.value) & 0xffff;
        return this;
    }

    or(other: Uint16) {
        if (!(other instanceof Uint16)) {
            throw new TypeError("Operand must be an instance of Uint16.");
        }
        this.value = (this.value | other.value) & 0xffff;
        return this;
    }

    xor(other: Uint16) {
        if (!(other instanceof Uint16)) {
            throw new TypeError("Operand must be an instance of Uint16.");
        }
        this.value = (this.value ^ other.value) & 0xffff;
        return this;
    }

    not() {
        this.value = ~this.value & 0xffff;
        return this;
    }

    leftShift(bits: number) {
        if (typeof bits !== "number" || !Number.isInteger(bits)) {
            throw new TypeError("Bits must be an integer.");
        }
        this.value = (this.value << bits) & 0xffff;
        return this;
    }

    rightShift(bits: number) {
        if (typeof bits !== "number" || !Number.isInteger(bits)) {
            throw new TypeError("Bits must be an integer.");
        }
        this.value = (this.value >>> bits) & 0xffff;
        return this;
    }

    toHexString() {
        return `0x${this.value.toString(16).padStart(4, "0")}`;
    }

    toString() {
        return this.value.toString(10);
    }

    encode() {
        const buffer = new Uint8Array(2);
        buffer[0] = (this.value >> 8) & 0xff;
        buffer[1] = this.value & 0xff;
        return buffer;
    }

    static decode(buffer: Uint8Array) {
        if (buffer.length !== 2) {
            throw new Error("Invalid buffer length");
        }
        const value = (buffer[0] << 8) | buffer[1];
        return new Uint16(value & 0xffff);
    }

    static from(value: number) {
        return new Uint16(value & 0xffff);
    }
}