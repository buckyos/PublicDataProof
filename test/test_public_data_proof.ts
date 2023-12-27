import hre, { ethers } from "hardhat";
import { mine } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { PublicDataProof } from "../typechain-types";
import { generateMixHash, HashType, MerkleTree } from "../scripts/generate_mixhash";
import { generateProof } from "../scripts/generate_proof";
import { HardhatEthersSigner } from '@nomicfoundation/hardhat-ethers/signers';
import fs from "node:fs";

describe("PublicDataProof", function () {
    let contract: PublicDataProof;
    let keccak256MixHash: Uint8Array = ethers.getBytes("0x800000000000433d5b1a08ad89b22622452cbfd2243b159fd5f4883503cd5518");
    let sha256MixHash: Uint8Array = ethers.getBytes("0x000000000000433d78736e40b1f9bfcefd9e7744984748da2ee528d00c6ef834");
    let correctMinIndex: number;
    let indexNumber: number;
    let signers: HardhatEthersSigner[];

    let data_fd = fs.openSync("test/testData.bin", "r");
    let orgLeafData = new Uint8Array(1024);

    before(async function () {
        contract = await (await hre.ethers.deployContract("PublicDataProof")).waitForDeployment();
        signers = await ethers.getSigners();
    });

    it("step chain", async function () {
        await mine();
    });

    it("size from hash", async function () {
        let size = await contract.lengthFromMixedHash(keccak256MixHash);
        expect(size).to.equal(17213);
    });

    it("find index for keccak256MixHash", async function () {
        indexNumber = await hre.ethers.provider.getBlockNumber();
        let [min_index, noise] = await generateProof("test/testData.bin", indexNumber, "test/test_merkle_keccak256.json", false);
        correctMinIndex = min_index;

        await mine();
    });

    it("show data proof with wrong index", async function () {
        let index = correctMinIndex + 1;
        let tree = MerkleTree.load(JSON.parse(fs.readFileSync("test/test_merkle_keccak256.json", {encoding: 'utf-8'})));
        let path = tree.getPath(index);
        orgLeafData.fill(0);
        fs.readSync(data_fd, orgLeafData, {position: index * 1024});
        
        let nonce = hre.ethers.getBytes((await hre.ethers.provider.getBlock(indexNumber))!.hash!);
        let leaf_data = new Uint8Array(Buffer.concat([orgLeafData, nonce]));

        let proof = tree.proofByPath(path, index, leaf_data);

        await expect(contract.showDataProof(keccak256MixHash, indexNumber, index, path, orgLeafData))
            .emit(contract, "ShowDataProof").withArgs(signers[0].address, keccak256MixHash, indexNumber, index, proof);
    });

    it("challenge it with new index", async function () {
        let tree = MerkleTree.load(JSON.parse(fs.readFileSync("test/test_merkle_keccak256.json", {encoding: 'utf-8'})));
        let path = tree.getPath(correctMinIndex);

        orgLeafData.fill(0);
        fs.readSync(data_fd, orgLeafData, {position: correctMinIndex * 1024});
        
        let nonce = hre.ethers.getBytes((await hre.ethers.provider.getBlock(indexNumber))!.hash!);
        let leaf_data = new Uint8Array(Buffer.concat([orgLeafData, nonce]));

        let proof = tree.proofByPath(path, correctMinIndex, leaf_data);

        await expect(contract.connect(signers[1]).showDataProof(keccak256MixHash, indexNumber, correctMinIndex,  path, orgLeafData))
            .emit(contract, "ShowDataProof").withArgs(signers[1].address, keccak256MixHash, indexNumber, correctMinIndex, proof)
            .emit(contract, "ProofPunish").withArgs(signers[0].address, keccak256MixHash);
    })

    it("get reward after sysConfigShowTimeout", async function () {
        await mine(640);
        await mine();
        let newIndex = 4;
        let tree = MerkleTree.load(JSON.parse(fs.readFileSync("test/test_merkle_keccak256.json", {encoding: 'utf-8'})));
        let path = tree.getPath(newIndex);

        orgLeafData.fill(0);
        fs.readSync(data_fd, orgLeafData, {position: newIndex * 1024});
        
        let nonce_height = await ethers.provider.getBlockNumber()-1;
        let nonce = hre.ethers.getBytes((await hre.ethers.provider.getBlock(nonce_height))!.hash!);
        let leaf_data = new Uint8Array(Buffer.concat([orgLeafData, nonce]));

        let proof = tree.proofByPath(path, newIndex, leaf_data);

        await expect(contract.connect(signers[0]).showDataProof(keccak256MixHash, nonce_height, newIndex,  path, orgLeafData))
            .emit(contract, "ShowDataProof").withArgs(signers[0].address, keccak256MixHash, nonce_height, newIndex, proof)
            .emit(contract, "ProofReward").withArgs(signers[1].address, keccak256MixHash);
    });
});