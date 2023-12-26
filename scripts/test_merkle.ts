import { ethers } from "hardhat";
import { MerkleTree, HashType } from "./ERCMerkleTree";
import fs from "node:fs"

function testMerkleTree(leaf_num: number) {
    let tree = new MerkleTree(HashType.Keccak256);
    let datas = [];
    for (let index = 0; index < leaf_num; index++) {
        let data = ethers.randomBytes(1024);
        datas.push(data);
        tree.addLeaf(data);
    }

    tree.calcTree();
    fs.writeFileSync("test_merkle_tree.json", JSON.stringify(tree.save()));
    for (let index = 0; index < leaf_num; index++) {
        let path = tree.getPath(index);
        let ret = tree.verify(path, index, datas[index]);
        console.log(`verify ${index} ret ${ret}`);
    }
}

testMerkleTree(6);