# ERC-XXXX 公共数据Hash （需要起一个更好的名字，不只用在公共数据里）公共数据Hash一种适合公共数据的新的Hash算法，相比全文Hash，有下面优点
0. 公共数据的Hash的设计目标是能支持一种相对够用的存储证明，推荐所有链上存储
    基于Nash共识的存储挑战的基本逻辑
1. 其构造并未降低安全性
2. 适当的PoW设计 
    挑战： 插入位置 （0-1024）,nonce
    结论： 选择插入原始nonce后的最合适叶子节点， 然后在插入位置之前插入自己的地址，再计算新的Nonce以让根hash符合难度条件
    10个块后结算，10个块内有人证明存在更合适的叶子节点可以拿走该用户的质押币。
    风险： 要防止对未充分散布的文件进行PoW奖励，因为别人没有完整数据，所以无法对其进行最合适叶子节点挑战
3. 基于该Hash对现有ERC的扩展建议 

## 目录结构
1. 算法说明文档
2. 生成数据hash的工具(nodejs,python,rust)
3. 对数据进行验证的solidy代码
4. 对数据进行PoW构造的工具
5. 对数据进行PoW验证的Solidy代码

## MixHash
High |-2-|----62----|----------192----------| Low
2:2bits的Hash算法选择为00使用SHA256，为10使用Keccak256 , 01,11保留
62：文件大小
192：根节点Hash的低192位

目标：存储证明里大量的数据只需要存储一次，然后通过存储证明来验证数据的存在



节点hash的大小是16byte （128bits）, 1024/16*2 = 32, 2^32*1K = 4T


针对特定PH的存储证明（最短）
1.块高度，说明是基于哪个快得到的nonce和pos
2.m,说明哪个叶子节点在插入了nonce后的根hash最小


挑战者：
1.提交一个更合适的m
2.给出path_to_m
3.给出m_leaf_data

提交存储证明的奖励是x（立刻得到）,供应方需要质押x*3
挑战成功可以得到x*3的奖励


## 私有数据存储证明
0. 用户(User)持有待保存的原始私有数据D
1. User决定把数据保存到供应商A，为A准备一个一次性的秘钥K,D通过K加密后得到D'。User将D'保存到A那，然后本地保留基于原始数据构造的挑战本和K
2. User认为供应商A丢失了D'(通常是通过链下判断），基于自己的挑战本在链上提出挑战：（一个32bytes Hash值） 
3. 供应商如果没有丢失数据，可以在Calldata里包含leaf_data （1KB）。挑战结束。供应商获胜。
4. 如果供应商认为Hash并不包含在D'中，提出挑战非法 1byte
5. 用户通过Call Data中的(index 4byte,默克尔路径,1KB )来证明挑战合法，用户获胜。

新方案可行么？
用户->nonce
供应商->m  ---> timeout,supplier_win
用户->path_m,leaf_data_m,new_m,path_new_m,leaf_data_new_m ---> user_win


## 公共数据存储证明 

0. 能提交存储证明获得奖励的用户被称作Supplier,Supplier需要准备一定的质押币。
1. 区块高度为h的区块Hash得到 32bytes的nonce值和 32-992 的插入位置Pos
2. 为了生成正确的存储证明，Supplier遍历所有的叶子节点，在该位置插入nonce值，选择最合适的叶子节点m。让插入后的根Hash最小
3. Supplier在插入位置之前再计算一个32bytes的noise值，使得新的LeafData可以让默克尔树根Hash符合一个难度条件（比如最低位多少是0）.对于同时进块的存储证明，难度高者胜出并得到奖励。
4. Supplier把存储证明{m,path,leaf_data,noise}提交到链上,即为一个有效的存储证明。可以拿到奖励.不需要PoW的场景可以进一步简化到 {h,m,path_m,m_leaf_data}
5. 链无法验证m是否正确，但其它拥有全量数据的Miner，如果发现m是伪造的，可以提交真实的{new_m,new_path_m,new_m_leaf_data} 来对已上连的存储证明进行挑战并在成功后赢得Supplier的质押币。 
6. 上述设计也可改成Supplier只提交m,挑战者提供path_m, m_leaf_data,但这会导致挑战者需要多1倍的手续费。如果获得的质奖励太少，那么挑战者可能不会提交挑战。

## 为什么私有数据和公有数据的存储证明不同？

公有数据方案的缺点是用户需要保存完整的数据才能挑战一个证明。而私有数据方案只需要保存一个挑战数据字典就好了。正确使用这两种方案可以有效的减少不同场景下的数据存储量。



## 公共数据存储证明不解决什么
不解决数据是否是公共的问题，也不解决数据是否被访问的问题。该证明的存在只是说明该数据的副本是存在的。


## 用于BTC网络
0. 存储方将一定的奖励保存到一个特定地址，该地址使用存储证明可以解开，并设定难度
1. 矿工提交有正确难度的noise,揭开该地址后可以得到BTC奖励



## 已知问题
最小文件大小问题：基于上述逻辑不适合保存太小的文件

这种Hash结构的文件拼接问题？文件A，文件B巧妙的构成文件C，然后利用文件A和文件B的存储证明就可以构造文件C的存储证明
