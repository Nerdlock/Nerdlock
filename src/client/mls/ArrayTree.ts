/**
 * Returns the exponent of the largest power of 2 less than x. Equivalent to Math.floor(Math.log2(x)).
 * @param x The number to compute the log2 of.
 */
function log2(x: number) {
    validateNumber(x);
    if (x === 0) {
        return 0;
    }
    let k = 0;
    while (x >> k > 0) {
        k++;
    }
    return k - 1;
}

/**
 * Validate if a number is a positive integer
 * @param n The number to validate.
 */
function validateNumber(n: number) {
    if (!Number.isInteger(n) || n < 0) {
        throw new Error("Invalid number");
    }
}

type IndexedType<T> = {
    data: T | undefined;
    index: number;
    left: () => IndexedType<T>;
    right: () => IndexedType<T>;
    parent: () => IndexedType<T>;
    sibling: () => IndexedType<T>;
    commonAncestorDirect: (other: IndexedType<T>) => IndexedType<T>;
    commonAncestorSemantic: (other: IndexedType<T>) => IndexedType<T>;
    directPath: () => IndexedType<T>[];
    copath: () => IndexedType<T>[];
};

type IndexedTypeWithData<T> = IndexedType<T> & { data: T };

export type { IndexedType }

/**
 * A binary-tree structure implemented as an array-based tree for the MLS ratchet tree.
 * Undefined values represent a blank node.
 */
export default class ArrayTree<T> {
    #nodes = new Array<T | undefined>();

    /**
     * The level of a node in the tree. Leaves are level 0, their parents
     * are level 1, etc. If a node's children are at different levels,
     * then its level is the max level of its children plus one.
     * @param node The node to get the level of.
     * @returns The level of the node.
     */
    level(node: IndexedType<T>) {
        const nodeIndex = node.index;
        if ((nodeIndex & 0x01) === 0) {
            return 0;
        }
        let k = 0;
        while (((nodeIndex >> k) & 0x01) === 1) {
            k++;
        }
        return k;
    }

    get leafCount() {
        const length = this.#nodes.length;
        if (length === 0) {
            return 0;
        }
        return (length >> 1) + 1;
    }

    /**
     * Get the root node of the tree.
     * @returns The root node of the tree.
     */
    get root() {
        const rootIndex = (1 << log2(this.#nodes.length)) - 1;
        const root = this.getIndexedNode(rootIndex);
        if (root === undefined) {
            throw new Error("Root not found");
        }
        return root;
    }

    /**
     * Get the left child of the given node.
     * @param node The node to get the left child of.
     * @returns The left child of the node.
     */
    left(node: IndexedType<T>) {
        const level = this.level(node);
        if (level === 0) {
            throw new Error("Node is a leaf");
        }
        const index = node.index ^ (0x01 << (level - 1));
        return this.getIndexedNode(index);
    }

    /**
     * Get the right child of the given node.
     * @param node The node to get the right child of.
     * @returns The right child of the node.
     */
    right(node: IndexedType<T>) {
        const level = this.level(node);
        if (level === 0) {
            throw new Error("Node is a leaf");
        }
        const index = node.index ^ (0x03 << (level - 1));
        return this.getIndexedNode(index);
    }

    parent(node: IndexedType<T>) {
        const nodeIndex = node.index;
        if (nodeIndex === this.root.index) {
            throw new Error("Cannot get parent of root");
        }
        const level = this.level(node);
        const b = (nodeIndex >> (level + 1)) & 0x01;
        const parentIndex = (nodeIndex | (1 << level)) ^ (b << (level + 1));
        return this.getIndexedNode(parentIndex);
    }

    sibling(node: IndexedType<T>) {
        const parent = this.parent(node);
        if (node.index < parent.index) {
            return this.right(parent);
        } else {
            return this.left(parent);
        }
    }

    directPath(node: IndexedType<T>) {
        const root = this.root;
        if (node.index === root.index) {
            return [];
        }
        const path: IndexedType<T>[] = [];
        let current = node;
        while (current.index !== root.index) {
            current = this.parent(current);
            path.push(current);
        }
        return path;
    }

    copath(node: IndexedType<T>) {
        if (node.index === this.root.index) {
            return [];
        }
        const path = this.directPath(node);
        path.unshift(node);
        path.pop();
        return path.map((p) => this.sibling(p));
    }

    commonAncestorSemantic(nodeA: IndexedType<T>, nodeB: IndexedType<T>) {
        const da = new Set([nodeA]).union(new Set(this.directPath(nodeA)));
        const db = new Set([nodeB]).union(new Set(this.directPath(nodeB)));
        const dab = new Set([...da].filter((node) => [...db].map((x) => x.index).includes(node.index)));
        if (dab.size === 0) {
            throw new Error("No common ancestor");
        }
        return [...dab].reduce((minNode, node) => (this.level(node) < this.level(minNode) ? node : minNode), [...dab][0]);
    }

    commonAncestorDirect(nodeA: IndexedType<T>, nodeB: IndexedType<T>) {
        const la = this.level(nodeA) + 1;
        const lb = this.level(nodeB) + 1;
        if (la <= lb && nodeA.index >> lb === nodeB.index >> lb) {
            return nodeB;
        } else if (lb <= la && nodeA.index >> la === nodeB.index >> la) {
            return nodeA;
        }
        // Handle other cases
        let an = nodeA.index;
        let bn = nodeB.index;
        let level = 0;
        while (an !== bn) {
            an = an >> 1;
            bn = bn >> 1;
            level++;
        }
        const index = (an << level) + (1 << (level - 1)) - 1;
        return this.getIndexedNode(index);
    }

    /**
     * Get all non-blank leaves in the tree.
     * @returns The non-blank leaves in the tree.
     */
    get leaves() {
        const leaves: IndexedTypeWithData<T>[] = [];
        let current = 0;
        while (current < this.#nodes.length) {
            const leaf = this.getIndexedNode(current);
            if (leaf.data != null) {
                leaves.push(leaf as IndexedTypeWithData<T>);
            }
            current += 2;
        }
        return leaves;
    }

    resolution(node: IndexedType<T>) {
        /*
        The resolution of a node is an ordered list of non-blank nodes that collectively cover all non-blank descendants of the node. The resolution of the root contains the set of keys that are collectively necessary to encrypt to every node in the group. The resolution of a node is effectively a depth-first, left-first enumeration of the nearest non-blank nodes below the node:

The resolution of a non-blank node comprises the node itself, followed by its list of unmerged leaves, if any.
The resolution of a blank leaf node is the empty list.
The resolution of a blank intermediate node is the result of concatenating the resolution of its left child with the resolution of its right child, in that order.
        */
    }

    /**
     * Get a node with the index property set.
     * @param index The index of the node to get.
     * @returns The node at the given index, with the index property set.
     */
    getIndexedNode(index: number) {
        if (index < 0 || index >= this.#nodes.length) {
            throw new Error("Invalid node index");
        }
        const node = this.#nodes[index];
        const indexedNode = <IndexedType<T>>{ data: node, index };
        indexedNode.left = () => this.left(indexedNode);
        indexedNode.right = () => this.right(indexedNode);
        indexedNode.parent = () => this.parent(indexedNode);
        indexedNode.sibling = () => this.sibling(indexedNode);
        indexedNode.commonAncestorDirect = (other) => this.commonAncestorDirect(indexedNode, other);
        indexedNode.commonAncestorSemantic = (other) => this.commonAncestorSemantic(indexedNode, other);
        indexedNode.directPath = () => this.directPath(indexedNode);
        indexedNode.copath = () => this.copath(indexedNode);
        return indexedNode;
    }

    setNode(index: number, node: T | undefined) {
        this.#nodes[index] = node;
    }

    /**
     * Get the number of nodes needed to represent a tree with the given number of leaves.
     * @param n The number of leaves in a tree.
     * @returns The width of the tree.
     */
    static width(n: number) {
        validateNumber(n);
        if (n === 0) {
            return 0;
        }
        return 2 * (n - 1) + 1;
    }
}