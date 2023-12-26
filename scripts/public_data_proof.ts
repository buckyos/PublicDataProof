import hre from "hardhat"
import fs from "node:fs"
import { HashType, MerkleTree } from "./ERCMerkleTree";

// 给定文件计算MixHash

function testMerkleTree(leaf_num: number) {
    let tree = new MerkleTree(HashType.Keccak256);
    let datas = [];
    for (let index = 0; index < leaf_num; index++) {
        let data = hre.ethers.randomBytes(1024);
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

testMerkleTree(30);

function generateMixHash(filePath: string, type: HashType, treeStorePath: string): Uint8Array {
    let file_op = fs.openSync(filePath, "r");
    let length = fs.statSync(filePath).size;
    let buf = new Uint8Array(1024);
    let begin = 0;
    let tree = new MerkleTree(type);
    while (true) {
        buf.fill(0);
        let n = fs.readSync(file_op, buf, {offset: begin, length: 1024});
        begin += n;
        if (n == 0) {
            break;
        }
        tree.addLeaf(buf);
    }
    // 如何算merkle hash？
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
// 根据nonce block high 计算存储证明（注意区分是否enable pow）
/*
function caclRoot(leaf_hash_array, type) {
    let current_len = leaf_hash_array.length;
    while (current_len > 1) {
        let pos = 0;
        for (let i = 0; i < current_len; i += 2) {
            if (i == current_len - 1) {
                leaf_hash_array[pos] = leaf_hash_array[i]
            } else {
                leaf_hash_array[pos] = calcHash(leaf_hash_array[i].concat(leaf_hash_array[i + 1]), type);
            }
            pos ++ ;
        }
        current_len = pos;
    }

    return leaf_hash_array[0];

}

function caclPath(leaf_hash_array,type,index) {
    let current_len = leaf_hash_array.length;
    let path = [];
    path.push(leaf_hash_array[index]);
    while (current_len > 1) {
        let pos = 0;
        for (let i = 0; i < current_len; i += 2) {
            if (i == current_len - 1) {
                leaf_hash_array[pos] = leaf_hash_array[i]
                if(i==index) {
                    path.push(0);
                    index = i / 2 + 1;
                }
            } else {
                leaf_hash_array[pos] = calcHash(leaf_hash_array[i].concat(leaf_hash_array[i + 1]), type);
                if(i==index) {
                    path.push(leaf_hash_array[i+1]);
                    index = i / 2;
                } else if(i+1==index) {
                    path.push(leaf_hash_array[i]);
                    index = i / 2; 
                }
            }

            pos ++ ;

        }
        current_len = pos;
    }

    return path;
}


function generateStorageProof(filePath: string, block: number, type: HashType): Uint8Array[] {
    uint256 nonce = 0;//getNonce(block);
    
    let file_op = fs.openSync(filePath, "r");
    let length = fs.statSync(filePath).size;

    let begin = 0;
    let leaf_hash = [];
    let buf_array = []
    while (true) {
        let buf = new Uint8Array(1024);
        buf.fill(0);
        let n = fs.readSync(file_op, buf, {offset: begin, length: 1024});
        if (n == 0) {
            break;
        }
        leaf_hash.push(calcHash(buf, type));
        buf_array.push(buf)
    }
    let min_hash = 0;
    let min_leaf = 0;
    
    for (let i = 0; i < leaf_hash.length; i++) {
        let new_leaf_hash= leaf_hash.clone();
        let buf2 = buf_array[i];
        buf2.append(nonce);

        new_leaf_hash[i] = calcHash(buf2, type);
        let new_root = caclRoot(new_leaf_hash,type);
        if(i==0) {
            min_hash = new_root;
        } else {
            if (new_root < min_hash) {
                min_hash = new_root;
                min_leaf = i;
            }
        }
    }

    let min_leaf_hash = leaf_hash.clone();
    let buf3 = buf_array[min_leaf];
    buf3.append(nonce);
    min_leaf_hash[min_leaf] = calcHash(buf3, type);
    let min_path = caclPath(min_leaf_hash,type,min_leaf)
}
*/