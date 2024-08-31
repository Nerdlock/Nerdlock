export default class MalformedObjectError extends Error {
    constructor(message: string, property: string, gotValue?: unknown) {
        super(message + `\nProperty: ${property}, got: ${gotValue}`);
        this.name = "MalformedObjectError";
    }
}
