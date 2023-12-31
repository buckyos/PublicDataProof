// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PublicDataProof {
    struct StoargeProof {
        uint256 nonce_block_high;
        uint256 proof_block;
        bytes32 proof_result;
        address prover;
    }
    mapping(bytes32 => StoargeProof) show_datas;

    uint256 sysConfigShowTimeout = 640;
    uint256 public constant POW_DIFFICULTY = 4;

    event ProofReward(address supplier, bytes32 dataMixedHash);
    event ProofPunish(address supplier, bytes32 dataMixedHash);
    event ShowDataProof(address supplier, bytes32 dataMixedHash, uint256 nonce_block_high, uint32 index_m, bytes32 proof_result);

    function showDataProof(bytes32 dataMixedHash, uint256 nonce_block_high,uint32 index_m, bytes16[] calldata m_path, bytes calldata leafdata) public {
        StoargeProof storage last_proof = show_datas[dataMixedHash];
        // 如果已经存在，判断区块高度差，决定这是一个新的挑战还是对旧的挑战的更新
        bool is_new_show = false;
        if(last_proof.proof_block == 0) {
            is_new_show = true;
        } else {
            if (block.number - last_proof.proof_block > sysConfigShowTimeout) {
                //Last Show Proof successed!
                //根据经济学模型对上一个Proof的提供者进行奖励
                emit ProofReward(last_proof.prover,dataMixedHash);
                last_proof.proof_block = 0;
                is_new_show = true;
            }
        } 
    
        require(is_new_show || last_proof.nonce_block_high == nonce_block_high, "nonce_block_high not match");
        (bytes32 root_hash,) = _verifyDataProof(dataMixedHash,nonce_block_high,index_m,m_path,leafdata,0);
        
        if(is_new_show) {
            last_proof.nonce_block_high = nonce_block_high;
            last_proof.proof_result = root_hash;
            last_proof.proof_block = block.number;
            last_proof.prover = msg.sender;
        } else {
            // 已经有挑战存在：判断是否结果更好，如果更好，更新结果，并更新区块高度
            if(root_hash < last_proof.proof_result) {
                //根据经济学模型对虚假的proof提供者进行惩罚
                emit ProofPunish(last_proof.prover,dataMixedHash);
                last_proof.proof_result = root_hash;
                last_proof.proof_block = block.number;
                last_proof.prover = msg.sender;
            } 
        }

        emit ShowDataProof(msg.sender, dataMixedHash, nonce_block_high, index_m, last_proof.proof_result);
    }

    function showStorageProofWihtPoW(bytes32 dataMixedHash, uint256 nonce_block_high,uint32 index_m, bytes16[] calldata m_path, bytes calldata leafdata,bytes32 noise) public {
        StoargeProof storage last_proof = show_datas[dataMixedHash];
        // 如果已经存在，判断区块高度差，决定这是一个新的挑战还是对旧的挑战的更新
        bool is_new_show = false;
        if(last_proof.proof_block == 0) {
            is_new_show = true;
        } else {
            if (block.number - last_proof.proof_block > sysConfigShowTimeout){
                //Last Show Proof successed!
                //根据经济学模型对上一个Proof的提供者进行奖励

                emit ProofReward(last_proof.prover,dataMixedHash);
                last_proof.proof_block = 0;
                is_new_show = true;
            } 
        }

        require(!is_new_show && last_proof.nonce_block_high == nonce_block_high, "nonce_block_high not match");
        (bytes32 root_hash,bytes32 pow_hash) = _verifyDataProof(dataMixedHash,nonce_block_high,index_m,m_path,leafdata,noise);
        // 判断新的root_hash是否满足pow难度,判断方法为后N个bits是否为0
        require(uint256(pow_hash) & ((1 << POW_DIFFICULTY) - 1) == 0, "pow difficulty not match");
        
        if(is_new_show) {
            last_proof.nonce_block_high = nonce_block_high;
            last_proof.proof_result = root_hash;
            last_proof.proof_block = block.number;
            last_proof.prover = msg.sender;
        } else {
            // 旧挑战：判断是否结果更好，如果更好，更新结果，并更新区块高度
            if(root_hash < last_proof.proof_result) {
                //根据经济学模型对虚假的proof提供者进行惩罚

                emit ProofPunish(last_proof.prover,dataMixedHash);
                last_proof.proof_result = root_hash;
                last_proof.proof_block = block.number;
                last_proof.prover = msg.sender;
            }
        }

        emit ShowDataProof(msg.sender, dataMixedHash, nonce_block_high, index_m, last_proof.proof_result);
    }

    function lengthFromMixedHash(bytes32 dataMixedHash) public pure returns (uint64) {
        return uint64(uint256(dataMixedHash) >> 192 & ((1 << 62) - 1));
    }
    
    function _verifyDataProof(bytes32 dataMixedHash,uint256 nonce_block_high, uint32 index, bytes16[] calldata m_path, bytes calldata leafdata, bytes32 noise) private view returns(bytes32,bytes32) {
        require(nonce_block_high < block.number, "invalid nonce_block_high");
        require(block.number - nonce_block_high < 256, "nonce block too old");

        bytes32 nonce = blockhash(nonce_block_high);

        //先验证index落在MixedHash包含的长度范围内
        require(index < (lengthFromMixedHash(dataMixedHash) >> 10) + 1, "invalid index");

        //验证leaf_data+index+path 和 dataMixedHash是匹配的,不匹配就revert
        // hash的头2bits表示hash算法，00 = sha256, 10 = keccak256
        uint8 hashType = uint8(uint256(dataMixedHash) >> 254);
        bytes32 dataHash;
        if (hashType == 0) {
            // sha256
            dataHash = _merkleRootWithSha256(m_path, index, _bytes32To16(sha256(leafdata)));
        } else if (hashType == 2) {
            // keccak256
            dataHash = _merkleRootWithKeccak256(m_path, index, _bytes32To16(keccak256(leafdata)));
        } else {
            revert("invalid hash type");
        }

        //验证leaf_data+index+path 和 dataMixedHash是匹配的,不匹配就revert
        // 只比较后192位
        require(dataHash & bytes32(uint256((1 << 192) - 1)) == dataMixedHash & bytes32(uint256((1 << 192) - 1)), "mixhash mismatch");

        // 不需要计算插入位置，只是简单的在Leaf的数据后部和头部插入，也足够满足我们的设计目的了？
        bytes memory new_leafdata;
        if(noise != 0) {
            //Enable PoW
            new_leafdata = bytes.concat(leafdata, nonce);
            bytes32 new_root_hash = _merkleRoot(hashType,m_path,index, _hashLeaf(hashType,new_leafdata));

            new_leafdata = bytes.concat(noise, leafdata, nonce);
            return (new_root_hash,_merkleRoot(hashType,m_path,index, _hashLeaf(hashType,new_leafdata)));
        } else {
            //Disable PoW
            new_leafdata = bytes.concat(leafdata, nonce);
            return (_merkleRoot(hashType,m_path,index, _hashLeaf(hashType,new_leafdata)),0);
        }
    }

    function _merkleRoot(uint8 hashType,bytes16[] calldata proof, uint32 leaf_index,bytes16 leaf_hash) internal pure returns (bytes32) {
        if (hashType == 0) {
            // sha256
            return _merkleRootWithSha256(proof, leaf_index, leaf_hash);
        } else if (hashType == 2) {
            // keccak256
            return _merkleRootWithKeccak256(proof, leaf_index, leaf_hash);
        } else {
            revert("invalid hash type");
        }
    }

    function _hashLeaf(uint8 hashType,bytes memory leafdata) internal pure returns (bytes16) {
        if (hashType == 0) {
            // sha256
            return _bytes32To16(sha256(leafdata));
        } else if (hashType == 2) {
            // keccak256
            return _bytes32To16(keccak256(leafdata));
        } else {
            revert("invalid hash type");
        }
    }

    // from openzeppelin`s MerkleProof.sol
    function _efficientKeccak256(bytes16 a, bytes16 b) private pure returns (bytes32 value) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, a)
            mstore(0x10, b)
            value := keccak256(0x00, 0x20)
        }
    }

    function _bytes32To16(bytes32 b) private pure returns (bytes16) {
        return bytes16(uint128(uint256(b)));
    }

    function _merkleRootWithKeccak256(bytes16[] calldata proof, uint32 leaf_index,bytes16 leaf_hash) internal pure returns (bytes32) {
        bytes16 currentHash = leaf_hash;
        bytes32 computedHash = 0;
        for (uint32 i = 0; i < proof.length; i++) {
            if (proof[i] != bytes32(0)) {
                if (leaf_index % 2 == 0) {
                    computedHash = _efficientKeccak256(currentHash, proof[i]);
                } else {
                    computedHash = _efficientKeccak256(proof[i], currentHash);
                }
                            
                currentHash = _bytes32To16(computedHash);
                leaf_index = leaf_index / 2;
            }
        }

        return computedHash;
    }

    // sha256要比keccak256贵，因为它不是一个EVM内置操作码，而是一个预置的内部合约调用
    // 当hash 1kb数据时，sha256要贵160，当hash 两个bytes32时，sha256要贵400
    function _merkleRootWithSha256(bytes16[] calldata proof, uint32 leaf_index, bytes16 leaf_hash) internal pure returns (bytes32) {
        bytes16 currentHash = leaf_hash;
        bytes32 computedHash = 0;
        for (uint32 i = 0; i < proof.length; i++) {
            if (proof[i] != bytes32(0)) {
                if (leaf_index % 2 == 0) {
                    computedHash = sha256(bytes.concat(currentHash, proof[i]));
                } else {
                    computedHash = sha256(bytes.concat(proof[i], currentHash));
                }
                currentHash = _bytes32To16(computedHash);
                leaf_index = leaf_index / 2;
            }
        }

        return computedHash;
    }
}