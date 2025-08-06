#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
基于SM3和RFC6962的Merkle树实现
支持10万叶子节点，并提供存在性证明和不存在性证明
"""

import math
from typing import List, Tuple, Optional, Union
from src.sm3_optimized import sm3_hash_optimized

# RFC6962中定义的常量
RFC6962_EMPTY_ROOT = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
RFC6962_LEAF_PREFIX = b'\x00'
RFC6962_NODE_PREFIX = b'\x01'


def hash_leaf(data: bytes) -> str:
    """
    计算叶子节点的哈希值（遵循RFC6962）
    :param data: 叶子节点数据
    :return: 哈希值（16进制字符串）
    """
    return sm3_hash_optimized(RFC6962_LEAF_PREFIX + data)


def hash_nodes(left: str, right: str) -> str:
    """
    计算内部节点的哈希值（遵循RFC6962）
    :param left: 左子节点哈希
    :param right: 右子节点哈希
    :return: 父节点哈希（16进制字符串）
    """
    # 将16进制字符串转换为字节
    left_bytes = bytes.fromhex(left)
    right_bytes = bytes.fromhex(right)
    return sm3_hash_optimized(RFC6962_NODE_PREFIX + left_bytes + right_bytes)


class MerkleTree:
    """
    基于SM3和RFC6962的Merkle树实现
    """

    def __init__(self, leaves: List[bytes]):
        """
        初始化Merkle树
        :param leaves: 叶子节点数据列表
        """
        # 存储叶子节点的哈希值
        self.leaf_hashes = [hash_leaf(leaf) for leaf in leaves]
        self.leaf_count = len(leaves)

        # 如果没有叶子节点，根节点为空哈希
        if self.leaf_count == 0:
            self.root = RFC6962_EMPTY_ROOT
            self.tree = []
            return

        # 计算树的高度
        self.height = math.ceil(math.log2(self.leaf_count))
        self.size = 2 ** self.height  # 树的大小（叶子节点数，向上取整为2的幂）

        # 如果叶子节点数不是2的幂，填充空节点
        if self.leaf_count < self.size:
            empty_hash = hash_leaf(b'')
            self.leaf_hashes += [empty_hash] * (self.size - self.leaf_count)

        # 构建Merkle树
        self.tree = [self.leaf_hashes.copy()]
        current_level = self.leaf_hashes

        # 从叶子节点向上构建各层
        for _ in range(self.height):
            next_level = []
            # 每两个节点合并为一个父节点
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                parent = hash_nodes(left, right)
                next_level.append(parent)
            self.tree.append(next_level)
            current_level = next_level

        # 根节点是树的最后一层的唯一节点
        self.root = self.tree[-1][0]

    def get_root(self) -> str:
        """获取Merkle树的根哈希"""
        return self.root

    def get_proof(self, index: int) -> Tuple[List[str], List[bool]]:
        """
        获取指定索引叶子节点的存在性证明
        :param index: 叶子节点索引
        :return: (证明路径列表, 每个证明节点是否在右侧的标志列表)
        """
        if index < 0 or index >= self.leaf_count:
            raise IndexError("叶子节点索引超出范围")

        # 调整索引以适应填充后的树
        adjusted_index = index
        proof = []
        is_right = []

        # 从叶子节点所在层向上收集证明
        for level in range(self.height):
            # 当前层的兄弟节点
            if adjusted_index % 2 == 0:
                # 左节点，兄弟是右节点
                sibling_index = adjusted_index + 1
                is_right_flag = True
            else:
                # 右节点，兄弟是左节点
                sibling_index = adjusted_index - 1
                is_right_flag = False

            # 添加兄弟节点的哈希到证明路径
            proof.append(self.tree[level][sibling_index])
            is_right.append(is_right_flag)

            # 上移到父节点索引
            adjusted_index = adjusted_index // 2

        return proof, is_right

    def verify_proof(self, leaf_data: bytes, proof: List[str], is_right: List[bool], root: str) -> bool:
        """
        验证叶子节点的存在性证明
        :param leaf_data: 叶子节点数据
        :param proof: 证明路径
        :param is_right: 每个证明节点是否在右侧的标志
        :param root: Merkle树根哈希
        :return: 证明是否有效
        """
        current_hash = hash_leaf(leaf_data)

        # 沿着证明路径向上计算
        for i in range(len(proof)):
            if is_right[i]:
                # 证明节点在右侧
                current_hash = hash_nodes(current_hash, proof[i])
            else:
                # 证明节点在左侧
                current_hash = hash_nodes(proof[i], current_hash)

        # 最终计算结果应等于根哈希
        return current_hash == root

    def get_non_existence_proof(self, index: int) -> Tuple[
        Optional[str], List[str], List[bool], Optional[str], List[str], List[bool]]:
        """
        获取指定索引位置的不存在性证明
        证明该索引位置没有对应的叶子节点
        :param index: 要证明不存在的索引
        :return: 左邻居证明和右邻居证明的元组
        """
        if index < 0 or index >= self.size:
            raise IndexError("索引超出范围")

        # 如果索引在有效叶子节点范围内，则存在，无法证明不存在
        if index < self.leaf_count:
            raise ValueError("该索引处存在叶子节点，无法生成不存在性证明")

        # 找到左侧最近的存在节点
        left_neighbor = None
        left_proof = []
        left_is_right = []

        for i in range(index - 1, -1, -1):
            if i < self.leaf_count:
                left_neighbor = i
                left_proof, left_is_right = self.get_proof(i)
                break

        # 找到右侧最近的存在节点
        right_neighbor = None
        right_proof = []
        right_is_right = []

        for i in range(index + 1, self.leaf_count):
            if i < self.leaf_count:
                right_neighbor = i
                right_proof, right_is_right = self.get_proof(i)
                break

        # 至少需要有一个邻居存在才能证明当前索引不存在
        if left_neighbor is None and right_neighbor is None:
            raise ValueError("无法生成不存在性证明：没有参考节点")

        return (left_neighbor, left_proof, left_is_right,
                right_neighbor, right_proof, right_is_right)

    def verify_non_existence(self, index: int,
                             left_data: Optional[bytes], left_proof: List[str], left_is_right: List[bool],
                             right_data: Optional[bytes], right_proof: List[str], right_is_right: List[bool]) -> bool:
        """
        验证不存在性证明
        :param index: 要证明不存在的索引
        :param left_data: 左邻居数据（如果存在）
        :param left_proof: 左邻居的证明路径
        :param left_is_right: 左邻居证明的方向标志
        :param right_data: 右邻居数据（如果存在）
        :param right_proof: 右邻居的证明路径
        :param right_is_right: 右邻居证明的方向标志
        :return: 证明是否有效
        """
        # 验证左邻居（如果存在）
        if left_data is not None:
            if not self.verify_proof(left_data, left_proof, left_is_right, self.root):
                return False

        # 验证右邻居（如果存在）
        if right_data is not None:
            if not self.verify_proof(right_data, right_proof, right_is_right, self.root):
                return False

        # 验证索引位置确实在左右邻居之间（如果都存在）
        if left_data is not None and right_data is not None:
            left_index = self.leaf_data_to_index(left_data)
            right_index = self.leaf_data_to_index(right_data)
            if not (left_index < index < right_index):
                return False

        return True

    def leaf_data_to_index(self, leaf_data: bytes) -> int:
        """
        根据叶子数据查找其在树中的索引
        注意：仅用于测试和演示，大规模数据中应使用更高效的查找方式
        """
        target_hash = hash_leaf(leaf_data)
        for i, leaf_hash in enumerate(self.leaf_hashes):
            if leaf_hash == target_hash and i < self.leaf_count:
                return i
        raise ValueError("叶子数据不在Merkle树中")


# 测试函数
def test_merkle_tree():
    """测试Merkle树实现"""
    # 测试1：基本功能测试
    leaves = [b"leaf1", b"leaf2", b"leaf3", b"leaf4"]
    merkle_tree = MerkleTree(leaves)

    # 验证根哈希计算
    assert merkle_tree.get_root() is not None

    # 验证存在性证明
    for i, leaf in enumerate(leaves):
        proof, is_right = merkle_tree.get_proof(i)
        assert merkle_tree.verify_proof(leaf, proof, is_right, merkle_tree.get_root()), \
            f"存在性证明验证失败，索引: {i}"

    # 测试2：叶子节点数不是2的幂
    leaves = [b"a", b"b", b"c"]
    merkle_tree = MerkleTree(leaves)
    assert merkle_tree.size == 4  # 向上取整为2^2=4

    # 测试3：空树
    empty_tree = MerkleTree([])
    assert empty_tree.get_root() == RFC6962_EMPTY_ROOT

    # 测试4：不存在性证明
    leaves = [b"0", b"1", b"2", b"3", b"4"]
    merkle_tree = MerkleTree(leaves)
    size = merkle_tree.size  # 应为8（2^3）

    # 尝试证明索引5不存在
    try:
        left_idx, left_proof, left_is_right, right_idx, right_proof, right_is_right = merkle_tree.get_non_existence_proof(
            5)

        # 验证证明
        left_data = leaves[left_idx] if left_idx is not None else None
        right_data = leaves[right_idx] if right_idx is not None else None

        assert merkle_tree.verify_non_existence(5, left_data, left_proof, left_is_right,
                                                right_data, right_proof, right_is_right), \
            "不存在性证明验证失败"
    except Exception as e:
        assert False, f"不存在性证明测试失败: {str(e)}"

    print("所有Merkle树测试通过!")


def test_large_merkle_tree():
    """测试大型Merkle树（10万叶子节点）"""
    import time

    # 创建10万个叶子节点
    print("创建10万个叶子节点...")
    num_leaves = 100000
    leaves = [f"leaf_{i}".encode() for i in range(num_leaves)]

    # 构建Merkle树
    print("构建Merkle树...")
    start_time = time.time()
    merkle_tree = MerkleTree(leaves)
    build_time = time.time() - start_time
    print(f"Merkle树构建完成，耗时: {build_time:.2f}秒")
    print(f"Merkle树根哈希: {merkle_tree.get_root()}")
    print(f"Merkle树高度: {merkle_tree.height}")
    print(f"Merkle树大小: {merkle_tree.size}")

    # 测试随机叶子节点的存在性证明
    test_indices = [0, 1, 99999, 50000, 12345]
    for idx in test_indices:
        print(f"测试索引 {idx} 的存在性证明...")
        start_time = time.time()
        proof, is_right = merkle_tree.get_proof(idx)
        proof_time = time.time() - start_time

        verify_start = time.time()
        valid = merkle_tree.verify_proof(leaves[idx], proof, is_right, merkle_tree.get_root())
        verify_time = time.time() - verify_start

        assert valid, f"大型Merkle树存在性证明验证失败，索引: {idx}"
        print(f"索引 {idx} 证明长度: {len(proof)}, 生成时间: {proof_time:.4f}秒, 验证时间: {verify_time:.4f}秒")

    # 测试不存在性证明
    print("测试不存在性证明...")
    idx = num_leaves  # 这个索引应该不存在
    try:
        left_idx, left_proof, left_is_right, right_idx, right_proof, right_is_right = merkle_tree.get_non_existence_proof(
            idx)

        left_data = leaves[left_idx] if left_idx is not None else None
        right_data = leaves[right_idx] if right_idx is not None else None

        valid = merkle_tree.verify_non_existence(idx, left_data, left_proof, left_is_right,
                                                 right_data, right_proof, right_is_right)

        assert valid, "大型Merkle树不存在性证明验证失败"
        print("不存在性证明验证成功")
    except Exception as e:
        assert False, f"大型Merkle树不存在性证明测试失败: {str(e)}"

    print("大型Merkle树测试通过!")


if __name__ == "__main__":
    test_merkle_tree()
    test_large_merkle_tree()
