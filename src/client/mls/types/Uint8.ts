/**
 * A class representing an 8-bit unsigned integer (uint8).
 */
export default class Uint8 {
    private _value: number | undefined;

    /**
     * Creates an instance of Uint8.
     * @param value - The initial value for the Uint8 instance.
     * @throws If the value is not within the range of a uint8.
     * @throws If the value is not an integer.
     */
    constructor(value = 0) {
        this.value = value; // Use setter to ensure validation
    }

    /**
     * Gets the current value of the Uint8 instance.
     * @returns The value as an 8-bit unsigned integer.
     */
    get value(): number {
        if (this._value === undefined) {
            throw new Error("Value not set");
        }
        return this._value & 0xff;
    }

    /**
     * Sets the value of the Uint8 instance with validation.
     * @param value - The value to set.
     * @throws If the value is not within the range of a uint8.
     * @throws If the value is not an integer.
     */
    set value(value: number) {
        if (typeof value !== "number" || !Number.isInteger(value)) {
            throw new TypeError("Value must be an integer.");
        }
        if (value < 0 || value > 0xff) {
            throw new RangeError("Value must be in the range of a uint8 (0 to 255).");
        }
        this._value = value & 0xff; // Ensure the value is treated as uint8
    }

    // Methods for addition, subtraction, bitwise operations, shifting, and encoding/decoding
    // are the same as in the Uint32 class, but adjusted for 8-bit operations.
    add(other: Uint8) {
        if (!(other instanceof Uint8)) {
            throw new TypeError("Operand must be an instance of Uint8.");
        }
        this.value = (this.value + other.value) & 0xff;
        return this;
    }

    subtract(other: Uint8) {
        if (!(other instanceof Uint8)) {
            throw new TypeError("Operand must be an instance of Uint8.");
        }
        this.value = (this.value - other.value) & 0xff;
        return this;
    }

    and(other: Uint8) {
        if (!(other instanceof Uint8)) {
            throw new TypeError("Operand must be an instance of Uint8.");
        }
        this.value = this.value & other.value & 0xff;
        return this;
    }

    or(other: Uint8) {
        if (!(other instanceof Uint8)) {
            throw new TypeError("Operand must be an instance of Uint8.");
        }
        this.value = (this.value | other.value) & 0xff;
        return this;
    }

    xor(other: Uint8) {
        if (!(other instanceof Uint8)) {
            throw new TypeError("Operand must be an instance of Uint8.");
        }
        this.value = (this.value ^ other.value) & 0xff;
        return this;
    }

    not() {
        this.value = ~this.value & 0xff;
        return this;
    }

    leftShift(bits: number) {
        if (typeof bits !== "number" || !Number.isInteger(bits)) {
            throw new TypeError("Bits must be an integer.");
        }
        this.value = (this.value << bits) & 0xff;
        return this;
    }

    rightShift(bits: number) {
        if (typeof bits !== "number" || !Number.isInteger(bits)) {
            throw new TypeError("Bits must be an integer.");
        }
        this.value = (this.value >>> bits) & 0xff;
        return this;
    }

    toHexString() {
        return `0x${this.value.toString(16).padStart(2, "0")}`;
    }

    toString() {
        return this.value.toString(10);
    }

    encode() {
        const buffer = new Uint8Array(1);
        buffer[0] = this.value & 0xff;
        return buffer;
    }

    static decode(buffer: Uint8Array) {
        if (buffer.length !== 1) {
            throw new Error("Invalid buffer length");
        }
        const value = buffer[0];
        return new Uint8(value & 0xff);
    }

    static from(value: number) {
        return new Uint8(value & 0xff);
    }
}
