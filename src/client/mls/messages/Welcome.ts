type Welcome = {};

function IsWelcome(object: unknown): object is Welcome {
    return typeof object === "object" && object !== null;
}

export type { Welcome };
export { IsWelcome };
