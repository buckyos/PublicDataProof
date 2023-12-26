import hre from "hardhat"
import fs from "node:fs"

// 给定文件计算MixHash
enum HashType {
    Sha256,
    Keccak256,
}

function calcHash(buf: Uint8Array, type: HashType): Uint8Array {
    let ret = type == HashType.Sha256 ? hre.ethers.sha256(buf) : hre.ethers.keccak256(buf);

    // 取低16bytes
    return hre.ethers.getBytes(ret).slice(16, 32);
}

function generateMixHash(filePath: string, type: HashType): Uint8Array {
    let leaf_hash = [];
    let file_op = fs.openSync(filePath, "r");
    let length = fs.statSync(filePath).size;
    let buf = new Uint8Array(1024);
    let begin = 0;
    while (true) {
        buf.fill(0);
        let n = fs.readSync(file_op, buf, {offset: begin, length: 1024});
        if (n == 0) {
            break;
        }
        leaf_hash.push(calcHash(buf, type));
    }
    // 如何算merkle hash？
    
    let full_hash = hre.ethers.randomBytes(32);
    new DataView(full_hash.buffer).setBigUint64(0, 93745654n, false);

    full_hash[0] &= (1 << 6) - 1;
    full_hash[0] |= 1 << 7;

    return full_hash;
}
// 根据nonce block high 计算存储证明（注意区分是否enable pow）