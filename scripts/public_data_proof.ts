import {ethers} from "hardhat"
import fs from "node:fs"
import { HashType, MerkleTree } from "./ERCMerkleTree";

// 给定文件计算MixHash

function testMerkleTree(leaf_num: number) {
    let tree = new MerkleTree(HashType.Keccak256);
    let datas = [];
    for (let index = 0; index < leaf_num; index++) {
        let data = ethers.randomBytes(1024);
        datas.push(data);
        tree.addLeaf(data);
    }

    tree.calcTree();
    fs.writeFileSync("merkle_tree.json", JSON.stringify(tree.save()));
    let random_leaf_index = Math.floor(Math.random() * (leaf_num-1));
    let path = tree.getPath(random_leaf_index);
    let ret = tree.verify(path, random_leaf_index, datas[random_leaf_index]);
    console.log("verify ret", ret);
}

// testMerkleTree(30);

let test_file_path = "C:\\TDDOWNLOAD\\MTool_8C34B84D.zip";

function generateMixHash(filePath: string, type: HashType, treeStorePath: string): Uint8Array {
    let file_op = fs.openSync(filePath, "r");
    let length = fs.statSync(filePath).size;
    let buf = new Uint8Array(1024);
    let begin = 0;
    let tree = new MerkleTree(type);
    process.stdout.write("begin read file\n");
    while (true) {
        process.stdout.clearLine(0);
        process.stdout.cursorTo(0);
        buf.fill(0);
        let n = fs.readSync(file_op, buf);
        if (n == 0) {
            break;
        }
        begin += n;
        process.stdout.write(`reading file: ${begin}/${length}`);
        tree.addLeaf(buf);
    }
    console.log("calcuteing tree...")
    tree.calcTree();
    let root_hash = tree.getRoot();
  
    //let full_hash =  caclRoot(leaf_hash,type)
    new DataView(root_hash.buffer).setBigUint64(0, BigInt(length), false);

    root_hash[0] &= (1 << 6) - 1;
    switch (type) {
        case HashType.Sha256:
            break;
        case HashType.Keccak256:
            root_hash[0] |= 1 << 7;
            break;
        default:
            throw new Error("unknown hash type");
    }

    fs.writeFileSync(treeStorePath, JSON.stringify(tree.save()));

    return root_hash;
}

function recoverHash(filePath: string, merkle_tree_file: string): Uint8Array {
    let length = fs.statSync(filePath).size;

    let tree = MerkleTree.load(JSON.parse(fs.readFileSync(merkle_tree_file, {encoding: 'utf-8'})));

    let root_hash = tree.getRoot();
  
    //let full_hash =  caclRoot(leaf_hash,type)
    new DataView(root_hash.buffer).setBigUint64(0, BigInt(length), false);

    root_hash[0] &= (1 << 6) - 1;
    switch (tree.type) {
        case HashType.Sha256:
            break;
        case HashType.Keccak256:
            root_hash[0] |= 1 << 7;
            break;
        default:
            throw new Error("unknown hash type");
    }

    return root_hash;
}

function getSize(mixedHashHex: string): number {
    let mixedHash = ethers.getBytes(mixedHashHex);
    mixedHash[0] &= (1 << 6) - 1;
    let size = new DataView(mixedHash.buffer).getBigUint64(0, false);

    return Number(size);

}

//let root_hash = recoverHash(test_file_path, "mtool_merkle.json");
//let root_hash = generateMixHash(test_file_path, HashType.Keccak256, "mtool_merkle.json");

//console.log("root_hash: ", ethers.hexlify(root_hash));
//console.log("file size:", getSize("0x800000000a6d9ffd7a8e5c956e40dea6ecb226aa0061d86513b9faff6bb15ec5"))

// 根据nonce block high 计算存储证明（注意区分是否enable pow）