export default class GREASEError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "GREASEError";
    }
}
