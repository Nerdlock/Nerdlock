type GroupInfo = {};

function IsGroupInfo(object: unknown): object is GroupInfo {
    return typeof object === "object" && object !== null;
}

export type { GroupInfo };
export { IsGroupInfo };
