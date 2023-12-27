// import hre from "hardhat"
import fs from "node:fs"
import SHA256 from 'crypto-js/sha256'


class MerkleTree {
    private hashType: MixHashType = MixHashType.Sha256
    private leaves: Uint8Array[] = []
    private layers: Uint8Array[][] = []
    private sortLeaves: boolean = false

    constructor (hashType: MixHashType) {
        this.hashType = hashType
    }

    getHashType(): MixHashType {
        return this.hashType;
    }

    initialLeaves(leaves: Uint8Array[]) {
        this.leaves = leaves;
        this.createHashes(leaves);
    }

    hashValue(value: Uint8Array): Uint8Array {
        if (this.hashType == MixHashType.Sha256) {
            return SHA256(value);
        } else if (this.hashType == MixHashType.Keccak256) {

        } else {
            throw new Error("invalid hash type");
        }
    }

    hashPair(left: Uint8Array, right: Uint8Array): Uint8Array {
        let concat = new Uint8Array(16);
        if (left.length == 8) {
            concat.set(left);
            concat.set(right, left.length);
        } else if (left.length == 16) {
            concat.set(left.slice(8, 16));
            concat.set(right.slice(8, 16), 8);
        } else {
            throw new Error("invalid hash length");
        }

        return this.hashValue(concat);
    }


    private createHashes (nodes: any[]) {
        this.layers = [nodes]
        while (nodes.length > 1) {
            const layerIndex = this.layers.length
            this.layers.push([])

            const layerLimit = nodes.length;

            for (let i = 0; i < nodes.length; i += 2) {
                if (i >= layerLimit) {
                    this.layers[layerIndex].push(...nodes.slice(layerLimit))
                    break
                } else if (i + 1 === nodes.length) {
                    if (nodes.length % 2 === 1) {
                        this.layers[layerIndex].push(nodes[i])
                        continue
                    }
                }

                const left = nodes[i]
                const right = i + 1 === nodes.length ? left : nodes[i + 1]

        
                let hash = this.hashPair(left, right)
                this.layers[layerIndex].push(hash)
            }

            nodes = this.layers[layerIndex]
        }
    }

    getRoot (): Uint8Array {
        return this.layers[this.layers.length - 1][0]
    }

    getProof (index: number): Uint8Array[] {
        const proof = []
        for (let i = 0; i < this.layers.length; i++) {
            const layer = this.layers[i]
            const isRightNode = index % 2
            const pairIndex = (isRightNode ? index - 1 : index + 1)
        
            if (pairIndex < layer.length) {
                proof.push(layer[pairIndex])
            }
        
            // set index to parent index
            index = (index / 2) | 0
        }
    
        return proof
    }

    getRootOfProof (index: number, leaf: Uint8Array, proof: Uint8Array[]): Uint8Array {
        let hash = leaf;
        for (let i = 0; i < proof.length; i++) {
            const isRightNode = index % 2
            const path = proof[i]
            const buffers: any[] = []
            if (isRightNode) {
                hash = this.hashPair(hash, path)
            } else {    
                hash = this.hashPair(path, hash)
            }
            buffers.push(hash)
            buffers[isRightNode ? 'push' : 'unshift'](path)

           
            // set index to parent index
            index = (index / 2) | 0
        }
        return hash
    }
}


enum MixHashType {
    Sha256,
    Keccak256,
}

class MixHash {
    readonly bytes: Uint8Array;

    constructor(hashType: MixHashType, length: bigint,root_hash: Uint8Array) {
        let bytes = new Uint8Array(32);
        let view = new DataView(bytes.buffer);
        view.setBigUint64(0, length, false);
        bytes[0] = bytes[0] & 0x3f;
        if (hashType == MixHashType.Sha256) {
            
        } else if (hashType == MixHashType.Keccak256) {
            bytes[0] = bytes[0] | 0x40;
        } else {
            throw new Error("invalid hash type");
        }
        bytes.set(root_hash.slice(8, 32), 8);
        this.bytes = bytes;
    }

    getLength(): bigint {
        let len_bytes = this.bytes.slice(0, 8);
        len_bytes[0] = len_bytes[0] & 0x3f;
        return new DataView(len_bytes.buffer).getBigUint64(0, false);
    }

    getHashType(): MixHashType {
        let type_bits = this.bytes[0] & 0xc0;
        if (type_bits == 0) {
            return MixHashType.Sha256;
        } else if (type_bits == 1) {
            return MixHashType.Keccak256;
        } else {
            throw new Error("invalid hash type");   
        }
    }

    compare(other: MixHash): number {
        for (let i = 0; i < 32; i++) {
            if (this.bytes[i] > other.bytes[i]) {
                return 1;
            } else if (this.bytes[i] < other.bytes[i]) {
                return -1;
            }
        }
        return 0
    }

    createFromFile(filePath: string, type: MixHashType): MixHash {
        let tree = new MerkleTree(type);
        let leaves = [];
        let file = fs.openSync(filePath, "r");
        let length = fs.statSync(filePath).size;
        let piece = 1024;
        let buf = new Uint8Array(piece);
        let begin = 0;
        while (true) {
            buf.fill(0);
            let n = fs.readSync(file, buf, {offset: begin, length: piece});
            if (n < piece) {
                break;
            }
            leaves.push(tree.hashValue(buf));
        }
        tree.initialLeaves(leaves);
        return new MixHash(type, length, tree.getRoot());
    } 
}

class PublicTarget {
    public readonly root: MixHash;
    public readonly nonce: Uint8Array;
    public readonly noncePosition: number;

    constructor(root: MixHash, nonce: Uint8Array, noncePosition: number) {
        this.root = root;
        this.nonce = nonce;
        this.noncePosition = noncePosition;
    }
}


class PublicProof {
    public readonly pieceIndex: number;
    public readonly pieceData: Uint8Array;
    public readonly proof: Uint8Array[];
    private readonly noise: undefined | Uint8Array;
   
    constructor(pieceIndex: number, pieceData: Uint8Array, proof: Uint8Array[], noise: undefined | Uint8Array) {
        this.pieceIndex = pieceIndex;
        this.pieceData = pieceData;
        this.proof = proof;
        this.noise = noise;
    }

    getRoot(target: PublicTarget): MixHash {
        let noncePiece = new Uint8Array(target.nonce.length + this.pieceData.length);
        noncePiece.set(this.pieceData.slice(0, target.noncePosition))
        noncePiece.set(target.nonce, target.noncePosition);
        noncePiece.set(this.pieceData.slice(target.noncePosition), target.noncePosition + target.nonce.length);
        
        let tree = new MerkleTree(target.root.getHashType());
        let leaf = tree.hashValue(noncePiece);
        return new MixHash(target.root.getHashType(), target.root.getLength(), tree.getRootOfProof(this.pieceIndex, leaf, this.proof));
    }

    getRootWithNoise(target: PublicTarget): MixHash {
        if (this.noise == undefined) {
            return this.getRoot(target);
        }
        let noncePiece = new Uint8Array(this.noise.length + target.nonce.length + this.pieceData.length);
        noncePiece.set(this.noise)
        noncePiece.set(this.pieceData.slice(0, this.noise.length + target.noncePosition))
        noncePiece.set(target.nonce, this.noise.length + target.noncePosition);
        noncePiece.set(this.pieceData.slice(target.noncePosition), this.noise.length + target.noncePosition + target.nonce.length);
        
        let tree = new MerkleTree(target.root.getHashType());
        let leaf = tree.hashValue(noncePiece);
        return new MixHash(target.root.getHashType(), target.root.getLength(), tree.getRootOfProof(this.pieceIndex, leaf, this.proof));
    }

    createPublicProofFromFile(filePath: string, target: PublicTarget, difficulty: undefined | MixHash): PublicProof {
        let leaves = [];
        let file = fs.openSync(filePath, "r");
        let length = fs.statSync(filePath).size;
        let piece = 1024;
        let originalTree = new MerkleTree(target.root.getHashType());
        {      
            let buf = new Uint8Array(piece);
            let begin = 0;
            while (true) {
                buf.fill(0);
                let n = fs.readSync(file, buf, {offset: begin, length: piece});
                if (n < piece) {
                    break;
                }
                leaves.push(originalTree.hashValue(buf));
            }
        }
    
        let roots : MixHash[] = [];
        for (let i = 0; i < leaves.length; i++) {
            let tree = new MerkleTree(target.root.getHashType());
            let tryLeaves = leaves.slice();
            for (let j = 0; j < i; j++) {
                tryLeaves[j] = leaves[j];
            }

            let buf  = new Uint8Array(piece);
            buf.fill(0);
            fs.readSync(file, buf, {offset: i * piece, length: piece});
            let noncePiece = new Uint8Array(target.nonce.length + piece);
            noncePiece.set(buf.slice(0, target.noncePosition))
            noncePiece.set(target.nonce, target.noncePosition);
            noncePiece.set(buf.slice(target.noncePosition), target.noncePosition + target.nonce.length);
            tryLeaves[i] = tree.hashValue(noncePiece);

            for (let j = i + 1; j < leaves.length; j++) {
                tryLeaves[j] = leaves[j];
            }
            tryLeaves.push(tree.hashValue(buf));
            tree.initialLeaves(tryLeaves);
            roots.push(new MixHash(target.root.getHashType(), length, tree.getRoot()));
        }

        let targetIndex: number = roots.reduce((iMin, x, i, arr) => x.compare(arr[iMin]) < 0 ? i : iMin, 0);
        originalTree.initialLeaves(leaves);
        let proof = originalTree.getProof(targetIndex);

        let pieceData  = new Uint8Array(piece);
        pieceData.fill(0);
        fs.readSync(file, pieceData, {offset: targetIndex * piece, length: piece});

        if (difficulty == undefined) {
            return new PublicProof(targetIndex, pieceData, proof, undefined);
        } 

        
        let noisePiece = new Uint8Array(32 + target.nonce.length + piece);
        noisePiece.set(pieceData.slice(0, target.noncePosition))
        noisePiece.set(target.nonce, target.noncePosition);
        noisePiece.set(pieceData.slice(target.noncePosition), target.noncePosition + target.nonce.length);

        while(true) {
            let noise = randomBytes(32);
            noisePiece.set(noise);
            let tree = new MerkleTree(target.root.getHashType());
            let noiseHash = tree.hashValue(noisePiece);
            leaves[targetIndex] = noiseHash;
            tree.initialLeaves(leaves);
            let root = new MixHash(target.root.getHashType(), target.root.getLength(), tree.getRoot());
            if (root.compare(difficulty) < 0) {
                return new PublicProof(targetIndex, pieceData, proof, noise);
            }
        }
    }

    verify(target: PublicTarget): boolean {
        let tree = new MerkleTree(target.root.getHashType());
        tree.hashValue(this.pieceData);
        let proofRoot = new MixHash(target.root.getHashType(), target.root.getLength(), tree.getRootOfProof(this.pieceIndex, this.pieceData, this.proof));
        return proofRoot.compare(target.root) == 0;
    }

    challenge(target: PublicTarget, oldProof: PublicProof): boolean {
        return this.getRoot(target).compare(oldProof.getRoot(target)) < 0;
    }

    compare(target: PublicTarget, other: PublicProof): number {
        return this.getRootWithNoise(target).compare(other.getRootWithNoise(target));
    }
}




