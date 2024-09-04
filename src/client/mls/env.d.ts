export type OmitMultiple<T, K extends Array<keyof T>> = Omit<T, K[number]>;
