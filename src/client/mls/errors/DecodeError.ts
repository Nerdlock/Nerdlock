export default class DecodeError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "DecodeError";
    }
}
