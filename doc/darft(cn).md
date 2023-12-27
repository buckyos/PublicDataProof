---
title: ERC-XXXX: MixHash与公共数据存储证明 
description: 在默克尔树的根Hash上进行升级，让保存在链上的数据Hash可以通过对应的密码学流程和简单的博弈流程提高其数据的可用性和可靠性。
author: Liu Zhicong(@waterflier), William Entriken (@fulldecent), Wei Qiushi (@weiqiushi),Si Changjun(@photosssa)
discussions-to: <URL>
status: Draft
type: Standards Track
category: ERC # Only required for Standards Track. Otherwise, remove this field.
created: 2023-12-21
requires: 165, 721, 1155 # Only required when you reference an EIP in the `Specification` section. Otherwise, remove this field.
---


## Abstract
This proposal introduces a design for `minimum value selection` storage proofs on Merkle trees. The design consists of two main components:

1. A hashing algorithm termed MixHash, aimed to replace the commonly used Keccak256 and SHA256 algorithms.
2. Public data storage proofs. This enables anyone to present a proof to a public network, verifying their possession of a copy of specific public data marked by MixHash.

Additionally, the proposal discusses the practical implementation of this design in various scenarios and suggests some improvements to the ERC-721 and ERC-1155 standards.

## Motivation
待补充


## Specification
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

### MixHash
MixHash is a Merkle tree root hash value that incorporates data length information. Its structure is as follows:
```
     +-----------256 bits MixHash-----------+
High |-2-|----62----|----------192----------| Low

2   bits: Hash algorithm selection, where 0b00 represents SHA256, and 0b10 represents Keccak256. (0b01, 0b11 are reserved)
62  bits: File size. Hence, MixHash can support file sizes up to 2^62-1.
192 bits: The lower 192 bits of the Merkel root node value constructed by the designated hash algorithm.
```

Given a file, we can construct a MixHash through the following defined steps:

1. File MUST Split into 1KB chunks. MUST Pad zeros to the end of the last chunk if needed.

2. Calculate the hash for each chunk and the low 128bits is the Merkle Tree leaf value.

3. Construct a Merkle tree , root node hash algorithm is 256bits, other node use low 128bits of the 256bits hash result.

4. Return the combination of hash type, the file size, and the low 192 bits of the Merkle tree root node hash.

MixHash retains a length of 256 bits, so replacing the widely used Keccak256 and SHA256 with MixHash incurs no additional cost. Although including the file length in the upper 62 bits compromises security to some extent, the 192-bit hash length is already sufficient for defending against hash collisions.

```
补充伪代码
```

### 公共数据存储证明
当我们用MixHash来标识一个公共数据之后，任何人都可以通过构造一个存储证明来证明自己拥有该数据的副本。下面是一个典型的使用公共数据存储证明的流程：

0. 能提交存储证明获得奖励的用户被称作Supplier。
1. Supplier基于区块高度为`h`的区块为数据D（其MixHash为`mix_hash_d`）准备存储证明。通过该区块得到本次证明的256bits的`nonce`值（通常直接使用区块的Hash）。
2. 为了生成正确的存储证明，Supplier需要遍历D的所有的1KB Chunk以寻找最佳的叶子节点`m`。寻找方法是挨个尝试在Chunk的尾部插入nonce值，让新的默克尔树根Hash最小。确定m后，提取出m的路径`m_path`和m的叶子节点值`m_leaf_data`。
3. Supplier使用 `{mix_hash_d, h, m, m_path, m_leaf_data}` 构造 `数据D在区块时间h`的存储证明，并提交到公共网络。
4. 公共网络可以基于`mix_hash_d`对`m`,`m_path`,`m_leaf_data`的正确性进行验证：验证`m`确实是D的一个Chunk。通过`h`可以对证明的时效性进行验证。正确性和时效性验证都通过后，公共网络用`nonce`值基于现有证明的信息计算得到`proof_result_m`并保存。
5. 公共网络并没有足够的信息验证该证明的最佳性，但其它拥有全量数据的Supplier，可以提交更好的（如果之前的证明是基于部分数据伪造的）`{mix_hash_d, h, better_m, better_m_path, better_m_leaf_data}` 来对已公开的存储证明进行挑战。
6. 公共网络可以通过对比`proof_result_m`和`proof_result_better_m`来判断挑战是否成功。挑战成功则旧的存储证明是伪造的。如果在一定时间里没有人挑战公开的存储证明，那么可以从博弈的角度认为该证明是正确的。
7. 为了支持良性的博弈，公共网络应该设计适当的经济模型，对于提供正确存储证明的的用户，对于提供虚假存储证明的用户进行惩罚。

理解上述流程后，让我们用伪代码来更精确的描述一下存储证明的生成过程和验证
```
function generateProof(mixHash, blockHeight,file) {
    nonce = getNonce(blockHeight);
    hash_type = getHashType(mixHash);
    chunk_hash_array = getChunkHashArray(file,hash_type);

    min_index = 0
    min_merkle_tree_root = MAX_UINT256
    min_chunk = None

    m_index = 0;
    for chunk in file {
      new_chunk = chunk + nonce;
      chunk_hash_array[m_index] = getChunkHash(new_chunk,hash_type);
      merkle_tree_root = getMerkleTreeRoot(chunk_hash_array,hash_type);
      chunk_hash_array[m_index] = getChunkHash(chunk,hash_type);
      if (merkle_tree_root < min_merkle_tree_root) {
        min_merkle_tree_root = merkle_tree_root;
        min_index = m_index;
        min_chunk = chunk;
      }
      m_index ++;
    }
    m_path = getMerkleTreePath(chunk_hash_array, min_index);
    return strorage_proof(mixHash, blockHeight, min_index, m_path, min_chunk);
}

function verifyDataProof(mixHash, blockHeight, m_index, m_path, m_leaf_data) {
    if(current_block_height - blockHeight > MAX_BLOCK_DISTANCE) {
       revert("proof expired");
    }
    hash_type = getHashType(mixHash);
    merkle_tree_root = getMerkleTreeRootFromPath(m_path,m_leaf_data,hash_type);
    if(low192(merkle_tree_root) != low192(mixHash)) {
       revert("invalid proof");
    }

    nonce = getNonce(blockHeight);
    proof_result = getMerkleTreeRootFromPath(m_path,m_leaf_data.append(nonce),hash_type);
    last_proof_result,last_prover = getProofResult(mixHash, blockHeight);
    if(proof_result < last_proof_result) {
      emit ProofPunish(last_prover);
      updateProofResult(mixHash, blockHeight, proof_result, msg.sender);
    } 
}
```
为了尽可能减少存储证明的大小，我们在具体实现中对getMerkleTreeRoot进行了一些优化：除了RootHash,其它Node的Hash值都只保留了低128bits。这样可以将一个完整的Merkle树的Hash值压缩到只有1/2大小。其完整实现可以参考后续的实现章节。

### 防御外部数据源攻击 (sourcing Attack)
通过上述流程可以看到，公共数据存储证明构造的核心是基于一个特定时刻产生的公开的、不重复的nonce值，需要在指定时间内遍历文件的全部内容并构造一个正确的证明。这个过程如果不加限制，那么就会受到外部数据源攻击：Supplier本地并不保存数据，而是在构造存储证明时，通过网络请求的方式获取数据。我们的设计是如何防止这种攻击的呢？

1. 限时回答：Supplier需要在指定的时间内提交存储证明。以太坊作为一个典型的公共网络，其出块时间为15秒左右，一个典型的限定区块间隔可以是2（MAX_BLOCK_DISTANCE = 2），这意味着Supplier必须在30秒以内完成存储证明的构造和提交。这个时间对于大部分的数据源来说是不够的完成传输的。因此，Supplier必须在本地保存数据，才能有机会在指定时间内构造存储证明。
2. 经济学博弈：基于公共数据存储证明的经济学模型通常给首个提交正确存储证明的Supplier奖励，这意味着从博弈的角度来说，使用外部数据源构造存储证明带来的固有延迟会减低提交存储证明的成功率，在经济上不如在本地保存数据的预期收益大。经济学模型会推动Supplier在本地保存数据。

#### 防御外部数据源攻击的成功率
使用区块间隔+首此提交优先的策略来防御外部数据源攻击在很多时候都是一个有效的策略。其有效的核心在于从本地读取文件的速度与从网络获取文件的速度之间的差异。我们可以通过下面的公式来定义防御外部数据源攻击的成功率R：
```
R = (TNetwork - TLocal) / AvgProofTime
```
AvgProofTime越大，防御外部数据源攻击的成功率越低。目前对AvgProofTime影响最大的因素是平均上链时间。比如对BTC网络来说，2个区块的时间大概为20分钟。在这么大的AvgProofTime情况下，我们可以引入能动态调整难度的PoW机制来进一步防御外部数据源攻击。让上述公式变成：
```
R = (TNetwork - TLocal) / (AvgProofTime-AvgPoWTime)
```
引入PoW思想后，存储证明提交的策略变成了：在指定时间内构造存储证明并提交，同时尽力完成更多的PoW计算，在有效证明时间窗口内，PoW计算量大的存储证明胜出。这样的机制可有效的在AvgProofTime较大的情况下防御外部数据源攻击。

在公共数据存储证明的设计中引入PoW机制并不复杂，一个简单的实现是修改第二步为：
```
2. 为了生成正确的存储证明，Supplier需要遍历D的所有的1KB Chunk以寻找最佳的叶子节点`m`。寻找方法是挨个尝试在Chunk的尾部插入nonce和自己构造的noise值，让新的默克尔树根Hash最小,并根据PoW难度要求，构造的proof_result_m的最后x位为0。确定m和noise后，提取出m的路径`m_path`和m的叶子节点值`m_leaf_data`。
```
根据上述修改调整后的伪代码如下：
```
POW_DIFFICULTY = 16;
function generateProofwithPoW(mixHash, blockHeight,file) {
    nonce = getNonce(blockHeight);
    hash_type = getHashType(mixHash);
    chunk_hash_array = getChunkHashArray(file,hash_type);

    min_index = 0
    min_merkle_tree_root = MAX_UINT256
    min_chunk = None

    m_index = 0;
    noise = 0;
    while(true) {
      for chunk in file {
        new_chunk = chunk + nonce + noise;
        chunk_hash_array[m_index] = getChunkHash(new_chunk,hash_type);
        merkle_tree_root = getMerkleTreeRoot(chunk_hash_array,hash_type);
        chunk_hash_array[m_index] = getChunkHash(chunk,hash_type);
        if (merkle_tree_root < min_merkle_tree_root) {
          min_merkle_tree_root = merkle_tree_root;
          min_index = m_index;
          min_chunk = chunk;
        }
        m_index ++;
      }
      if(last_zero_bits(min_merkle_tree_root) >= POW_DIFFICULTY) {
        break;
      }
      noise++
    }
    m_path = getMerkleTreePath(chunk_hash_array, min_index);
    return strorage_proof(mixHash, blockHeight, min_index, m_path, min_chunk,noise);
}
```
应用该机制后，产生存储证明的成本会增加，和我们期望降低公共数据的广泛有效存储的初衷有所背离。而且高度依赖该机制的经济模型可能会让在PoW上用专门硬件建立巨大优势的Supplier破坏基础的博弈可参与性，降低公共数据分布的广泛性。因此我们建议应尽量不要启用PoW机制。

### 局限性

1. 本文讨论的存储证明并不不适合保存太小的文件，小文件本质上难以防御外部数据源攻击。
2. 公共数据存储证明并不解决数据是否是真正公共的问题，因此在使用时需注意根据场景对MixHash是否是公共的进行验证（这通常并不会很容易）。如果允许Supplier对任意MixHash进行存储证明的提交并获得奖励，那么Supplier一定会构造一个只有自己的拥有的数据，并通过构造攻击来获得奖励。最终导致整个生态的崩溃。

### ERC扩展建议：追踪高价值的公共数据
我们可以基于EVM现有生态来确认一个MixHash是否是公共数据，并追踪其价值。对于任何与非结构化数据有关的合约，都可以实现接口`ERCPublicDataOwner`，该接口会判断一个确定的MixHash是否与当前合约有关，并尝试返回一个MixHash对应的Owner地址。同时，对于现有，已经广泛认可的NFT生态，我们建议新的ERC-721和ERC-1155的合约可以实现一个新的扩展接口`ERC721MixHashVerfiy`，该接口可以明确的将一个NFT与一个MixHash对应起来。具体的接口定义如下：

```solidity
/// @title ERCPublicDataOwner Standard, 得到制定MixHash的Owner
///  Note: the ERC-165 identifier for this interface is <ERC-Number>.
interface ERCPublicDataOwner {
    /**
        @notice Queries Owner of public data determined by Mixhash
        @param  mixHash    Mixhash you want to query
        @return            If it is an identified public data, return the Owner address, otherwise 0x0 will be returned
    */
    function getPublicDataOwner(bytes32 mixHash) external view returns (address);
}
```

The `ERC721MixHashVerfiy` extension is OPTIONAL for ERC-721 smart contracts or ERC-1155 smart contracts. This extension can help establish a relationship between specified NFT and MixHash.
```solidity
/// @title ERC721MixHashVerfiy Extension, optional extension
///  Note: the ERC-165 identifier for this interface is <ERC-Number>.
interface ERC721MixHashVerfiy{
    /**
        @notice Is the tokenId of the NFT is the Mixhash?
        @return           True if the tokenId is MixHash, false if not
    */
    function tokenIdIsMixHash() external view returns (bool); 
    
    /**
        @notice Queries NFT's MixHash
        @param  _tokenId  NFT to be querying
        @return           The target NFT corresponds to MixHash, if it is not Mixhash, it returns 0x0
    */
    function tokenDataHash(uint256 _tokenId) external view returns (bytes32);
}
```

## Rationale

存储证明（又常被称作时空证明）是一个长期受到关注的问题，已经有很多的实现和相关的项目。

1. 和已有的，基于零知识证明的的副本证明的相比，我们的存储证明是基于"Nash Consensus"的，其核心在于:
  a. 公共网络（链上）并不能对证明的最佳性进行验证，而是依赖经济学博弈。这极大的降低了构造和验证的成本
  b. 没有价值的数据通常也没有博弈价值，会自然的从系统中淘汰。不承诺虚无缥缈的永久存储。
2. 能完全通过智能合约实现(目前的参考实现的GAS费有点高)，分离了存储证明和经济模型
3. 针对公共数据，我们并不严格防御女巫攻击。所谓女巫攻击，是指Supplier利用n个身份，承诺存储n份数据D，而实际上存储小于n份（比如1份），但是却提供了n份存储证明，攻击成功。要严格防范女巫攻击，本质上是在给数据存储附加更多的额外成本。本文的存储证明的核心是通过存储证明和不同经济模型的组合，提高公共数据副本存在的概率，而不是需要严格的定义有多少个副本。因此，站在公共数据存储证明的设计角度，我们不需要防御女巫攻击。

## Backwards Compatibility
使用HashType能让存储证明兼容EVM兼容的公共区块链系统，也能兼容BTC-Like的公共区块链系统。实际上,MixHash可以成为一个新的跨链价值锚定：可以在不同的公共区块链网络里，用不同的模型对MixHash表达同一份数据的价值进行追踪，实现跨链价值的聚合。考虑到目前向下兼容的需要，我们把MixHash的默认HashType设置为了SHA256. HashType还有2类未用，也为未来的扩展留出足够的空间。


## Security Considerations
本存储证明围绕公共数据展开，在展示存储证明时，常常会把数据的1KB片段发送到公共网络。因此请不要在隐私数据上使用本文设计的存储证明。

MixHash的设计能够支持隐私文件的存储证明，但需要在原始数据的处理和存储证明的构造上进行一些调整。详细讨论隐私文件的存储证明的设计超出了本文的范畴。实际上Reference Implementation章节里提到的一些项目同时使用了公共数据存储证明和隐私数据存储证明。

## Test Cases
PublicDataProofDemo includes test cases written using Hardhat.

## Reference Implementation
1. 参考实现
    - PublicDataProofDemo
2. 使用了本文设计的项目
    - DMC公共数据铭文 项目，提供了完整的经济模型
    
3. 了解存储证明诞生的背景
    - DMC Main Chain
    - CYFS

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).

