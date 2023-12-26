import { throwError, compareBytes, concatBytes, equalsBytes } from "./ERCMerkleTreeUtil"
import { ethers } from "hardhat";

const leftChildIndex = (i: number) => 2 * i + 1;
const rightChildIndex = (i: number) => 2 * i + 2;
const parentIndex     = (i: number) => i > 0 ? Math.floor((i - 1) / 2) : throwError('Root has no parent');
const siblingIndex    = (i: number) => i > 0 ? i - (-1) ** (i % 2)     : throwError('Root has no siblings');

const isValidMerkleNode = (node: Uint8Array) => node instanceof Uint8Array && node.length === 16;
const checkValidMerkleNode = (node: Uint8Array) => void (isValidMerkleNode(node) || throwError('Merkle tree nodes must be Uint8Array of length 32'));

const isTreeNode        = (tree: unknown[], i: number) => i >= 0 && i < tree.length;
const isInternalNode    = (tree: unknown[], i: number) => isTreeNode(tree, leftChildIndex(i));
const isLeafNode        = (tree: unknown[], i: number) => isTreeNode(tree, i) && !isInternalNode(tree, i);

const checkLeafNode        = (tree: unknown[], i: number) => void (isLeafNode(tree, i)     || throwError('Index is not a leaf'));

function hashPair(a: Uint8Array, b: Uint8Array): Uint8Array {
    return ethers.getBytes(ethers.keccak256(concatBytes(...[a, b].sort(compareBytes))))
};

export function makeMerkleTree(leaves: Uint8Array[]): Uint8Array[] {
    leaves.forEach(checkValidMerkleNode);

    if (leaves.length === 0) {
        throw new Error('Expected non-zero number of leaves');
    }

    const tree = new Array<Uint8Array>(2 * leaves.length - 1);

    for (const [i, leaf] of leaves.entries()) {
        tree[tree.length - 1 - i] = leaf;
    }
    for (let i = tree.length - 1 - leaves.length; i >= 0; i--) {
        tree[i] = hashPair(
            tree[leftChildIndex(i)]!,
            tree[rightChildIndex(i)]!,
        );
    }

    return tree;
}

export function processProof(leaf: Uint8Array, proof: Uint8Array[]): Uint8Array {
    checkValidMerkleNode(leaf);
    proof.forEach(checkValidMerkleNode);

    return proof.reduce(hashPair, leaf);
}

export function isValidMerkleTree(tree: Uint8Array[]): boolean {
    for (const [i, node] of tree.entries()) {
        if (!isValidMerkleNode(node)) {
            return false;
        }

        const l = leftChildIndex(i);
        const r = rightChildIndex(i);

        if (r >= tree.length) {
            if (l < tree.length) {
                return false;
            }
        } else if (!equalsBytes(node, hashPair(tree[l]!, tree[r]!))) {
            return false;
        }
    }

    return tree.length > 0;
}

export function getProof(tree: Uint8Array[], index: number): Uint8Array[] {
    checkLeafNode(tree, index);
  
    const proof = [];
    while (index > 0) {
      proof.push(tree[siblingIndex(index)]!);
      index = parentIndex(index);
    }
    return proof;
  }