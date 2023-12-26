import { compareBytes, equalsBytes, checkBounds, throwError } from './ERCMerkleTreeUtil';
import { getProof, isValidMerkleTree, makeMerkleTree, processProof } from './ERCMerkleTreeCore';

import { ethers } from 'hardhat';

export enum HashType {
    Sha256,
    Keccak256,
}

export function calcHash(buf: Uint8Array, type: HashType): Uint8Array {
    let ret = type == HashType.Sha256 ? ethers.sha256(buf) : ethers.keccak256(buf);

    // 取低16bytes
    return ethers.getBytes(ret).slice(16, 32);
}

// input any data, return 16 bytes keccak256 hash
function standardLeafHash(value: Uint8Array, type: HashType): Uint8Array {
    return calcHash(value, type)
}

interface StandardMerkleTreeData {
    format: 'ercmerkle-v1';
    tree: string[];
    values: {
        value: Uint8Array;
        treeIndex: number;
    }[];
    type: HashType;
}

export class StandardMerkleTree {
    private readonly hashLookup: { [hash: string]: number };

    private constructor(
        private readonly tree: Uint8Array[],
        private readonly values: { value: Uint8Array, treeIndex: number }[],
        private readonly type: HashType,
    ) {
        this.hashLookup =
            Object.fromEntries(values.map(({ value }, valueIndex) => [
                ethers.hexlify(standardLeafHash(value, type)),
                valueIndex,
            ]));
    }

    static of(values: Uint8Array[], type: HashType) {
        const hashedValues = values
            .map((value, valueIndex) => ({ value, valueIndex, hash: standardLeafHash(value, type) }))
            .sort((a, b) => compareBytes(a.hash, b.hash));

        const tree = makeMerkleTree(hashedValues.map(v => v.hash));

        const indexedValues = values.map(value => ({ value, treeIndex: 0 }));
        for (const [leafIndex, { valueIndex }] of hashedValues.entries()) {
            indexedValues[valueIndex]!.treeIndex = tree.length - leafIndex - 1;
        }

        return new StandardMerkleTree(tree, indexedValues, type);
    }

    static load(data: StandardMerkleTreeData): StandardMerkleTree {
        if (data.format !== 'ercmerkle-v1') {
            throw new Error(`Unknown format '${data.format}'`);
        }
        return new StandardMerkleTree(
            data.tree.map((value) => ethers.getBytes(value)),
            data.values,
            data.type,
        );
    }

    static verify(root: string, type: HashType, leaf: Uint8Array, proof: string[]): boolean {
        const impliedRoot = processProof(standardLeafHash(leaf, type), proof.map((value) => ethers.getBytes(value)));
        return equalsBytes(impliedRoot, ethers.getBytes(root));
    }

    dump(): StandardMerkleTreeData {
        return {
            format: 'standard-v1',
            tree: this.tree.map(ethers.hexlify),
            values: this.values,
            type: this.type,
        };
    }

    get root(): string {
        return ethers.hexlify(this.tree[0]!);
    }

    *entries(): Iterable<[number, Uint8Array]> {
        for (const [i, { value }] of this.values.entries()) {
            yield [i, value];
        }
    }

    validate() {
        for (let i = 0; i < this.values.length; i++) {
            this.validateValue(i);
        }
        if (!isValidMerkleTree(this.tree)) {
            throw new Error('Merkle tree is invalid');
        }
    }

    leafHash(leaf: Uint8Array): string {
        return ethers.hexlify(standardLeafHash(leaf, this.type));
    }

    leafLookup(leaf: Uint8Array): number {
        return this.hashLookup[this.leafHash(leaf)] ?? throwError('Leaf is not in tree');
    }

    getProof(leaf: number | Uint8Array): string[] {
        // input validity
        const valueIndex = typeof leaf === 'number' ? leaf : this.leafLookup(leaf);
        this.validateValue(valueIndex);

        // rebuild tree index and generate proof
        const { treeIndex } = this.values[valueIndex]!;
        const proof = getProof(this.tree, treeIndex);

        // sanity check proof
        if (!this._verify(this.tree[treeIndex]!, proof)) {
            throw new Error('Unable to prove value');
        }

        // return proof in hex format
        return proof.map(ethers.hexlify);
    }

    verify(leaf: number | Uint8Array, proof: string[]): boolean {
        return this._verify(this.getLeafHash(leaf), proof.map((value) => ethers.getBytes(value)));
    }

    private _verify(leafHash: Uint8Array, proof: Uint8Array[]): boolean {
        const impliedRoot = processProof(leafHash, proof);
        return equalsBytes(impliedRoot, this.tree[0]!);
    }

    private validateValue(valueIndex: number): Uint8Array {
        checkBounds(this.values, valueIndex);
        const { value, treeIndex } = this.values[valueIndex]!;
        checkBounds(this.tree, treeIndex);
        const leaf = standardLeafHash(value, this.type);
        if (!equalsBytes(leaf, this.tree[treeIndex]!)) {
            throw new Error('Merkle tree does not contain the expected value');
        }
        return leaf;
    }

    private getLeafHash(leaf: number | Uint8Array): Uint8Array {
        if (typeof leaf === 'number') {
            return this.validateValue(leaf);
        } else {
            return standardLeafHash(leaf, this.type);
        }
    }
}
