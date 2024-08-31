export default class InvalidObjectError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "InvalidObjectError";
    }
}