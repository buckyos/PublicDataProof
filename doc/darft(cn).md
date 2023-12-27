---
title: 一种支持链下数据存储证明的Hash算法 （或则存储证明）
description: 在默克尔树的根Hash上进行升级，让保存在链上的数据Hash可以通过对应的密码学流程和简单的博弈流程提高其数据的可用性和可靠性。
author: waterflier,William,weiqiushi,sisi,
discussions-to: <URL>
status: Draft
type: <Standards Track, Meta, or Informational>
category: ERC # Only required for Standards Track. Otherwise, remove this field.
created: 2023-12-21
requires: 721,1155 # Only required when you reference an EIP in the `Specification` section. Otherwise, remove this field.
---


## Abstract
本文提出了一种在默克尔树上做最小值选择的存储证明设计。该设计主要包含两部分
1. 我们称作MixHash的新Hash算法，用来替代今天广泛使用的Keccak256和SHA256
2. 公共数据存储证明。任何人都可以向一个公共的网络提交一个证明，证明自己拥有用MixHash标识的特定公共数据的副本。

本文还讨论了在一些实际的场景下，如何应用上述设计。  
本文还提出了对ERC721和ERC1155的一些改进建议。  


## Motivation
最后写，内容是存储证明的发展和迫切需要解决的问题


## Specification
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

在展开说明所有的设计细节之前，我们先来看一下整体的流程。
 ```mermaid

```

### MixHash
MixHash是包含了数据长度信息的数据的Merkle树根Hash值。其构成如下：
```
     +-----------256 bits MixHash ----------+
High |-2-|----62----|----------192----------| Low

2   bits: Hash算法选择，0b00为SHA256，0b10为Keccak256.(0b01,0b11保留)
62  bits：文件大小。因此MixHash最大支持表达2^62-1的文件大小
192 bits：通过指定Hash算法构造的Merkel根节点值的低192位
```
给定一个文件，我们可以通过如下确定步骤构造出一个MixHash

1. File MUST Split into 1KB chunks. MUST Pad zeros to the end of the last chunk if needed.

2. Calculate the hash for each chunk and the low 128bits is the Merkle Tree leaf value.

3. Construct a Merkle tree , root node hash algorithm is 256bits, other node use low 128bits of the 256bits hash result.

4. Return the combination of hash type, the file size, and the low 192 bits of the Merkle tree root node hash.

MixHash的长度依旧为256Bits,因此使用MixHash替代被广泛使用的Kaekk256和SHA256，没有任何额外的成本。在高62bits包含了文件的长度虽然在安全性上有一定的损失，但192bits的Hash长度在防御Hash碰撞已经完全足够了。


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

### 防御外部数据源攻击的成功率
使用区块间隔+首此提交优先的策略来防御外部数据源攻击在很多时候都是一个有效的策略。其有效的核心在于从本地读取文件的速度与从网络获取文件的速度之间的差异。我们可以通过下面的公式来定义防御外部数据源攻击的成功率R：
```
R = (TNetwork - TLocal) / AvgProofTime
```
AvgProofTime越大，义防御外部数据源攻击的成功率越低。目前对AvgProofTime影响最大的因素是平均上链时间。比如对BTC网络来说，2个区块的时间大概为20分钟。在这么大的AvgProofTime情况下，我们可以引入能动态调整难度的PoW机制来进一步防御外部数据源攻击。让上述公式变成：
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
function generateProofwithPow(mixHash, blockHeight,file) {
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
      if(min_merkle_tree_root.last_bits() >= POW_DIFFICULTY) {
        break;
      }
      noise++
    }
    m_path = getMerkleTreePath(chunk_hash_array, min_index);
    return strorage_proof(mixHash, blockHeight, min_index, m_path, min_chunk,noise);
}
```
应用该机制后，产生存储证明的成本会增加，和我们期望降低公共数据的广泛有效存储的初衷有所背离。而且高度依赖PoW的经济模型可能会让在PoW上用专门硬件建立巨大优势的Supplier破坏基础的博弈可参与性，降低公共数据分布的广泛性。因此我们建议应尽量不要启用PoW机制。

### 注意事项与局限性

1. 最小文件大小问题：基于上述逻辑不适合保存太小的文件，小文件本质上难以防御外部数据源攻击
2. 不解决数据是否是公共的问题，也不解决数据是否被访问的问题。该证明的存在只是说明该数据的副本是存在的。

### ERC扩展建议：追踪高价值的数据

```
//Review:这个作为ERC的一部分，要仔细考虑一下
interface IERCPublicDataContract {
    //return the owner of the data
    function getDataOwner(bytes32 dataHash) external view returns (address);
}
```


```
interface IERC721VerfiyDataHash{
    //return token data hash
    function tokenDataHash(uint256 _tokenId) external view returns (bytes32);
}
```



## Rationale

<!--
  The rationale fleshes out the specification by describing what motivated the design and why particular design decisions were made. It should describe alternate designs that were considered and related work, e.g. how the feature is supported in other languages.

  The current placeholder is acceptable for a draft.

  TODO: Remove this comment before submitting
-->
本问讨论的存储证明的核心是 基于“Nash Consensus” 的博弈性共识，而不是传统的零知识证明性共识。

## Backwards Compatibility

<!--

  This section is optional.

  All EIPs that introduce backwards incompatibilities must include a section describing these incompatibilities and their severity. The EIP must explain how the author proposes to deal with these incompatibilities. EIP submissions without a sufficient backwards compatibility treatise may be rejected outright.

  The current placeholder is acceptable for a draft.

  TODO: Remove this comment before submitting
-->

1. 虽然存储证明的设计是算法性的，架构无关的。但现在的设计考虑了能在主流的L1上实现
2. 使用HashType来兼容现有的L1，并未未来的扩展留出空间
3. 目前HashType预留了4种，已经使用了两种。如下表：


## Reference Implementation

简单实现
1. 构造MixHash

2. 生成存储证明

3. 验证存储证明

```solidity
function verifyDataProof(bytes32 meta) {

}


```



## Security Considerations

<!--
  All EIPs must contain a section that discusses the security implications/considerations relevant to the proposed change. Include information that might be important for security discussions, surfaces risks and can be used throughout the life cycle of the proposal. For example, include security-relevant design decisions, concerns, important discussions, implementation-specific guidance and pitfalls, an outline of threats and risks and how they are being addressed. EIP submissions missing the "Security Considerations" section will be rejected. An EIP cannot proceed to status "Final" without a Security Considerations discussion deemed sufficient by the reviewers.

  The current placeholder is acceptable for a draft.

  TODO: Remove this comment before submitting
-->

隐私安全

数据可靠性

面向存储证明的场常见攻击

系统的安全边界

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).