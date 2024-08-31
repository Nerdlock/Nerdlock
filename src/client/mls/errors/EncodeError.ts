export default class EncodeError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "EncodeError";
    }
}