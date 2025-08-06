#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Merkle树测试
验证Merkle树的构建、存在性证明和不存在性证明
"""

import unittest
import random
from src.merkle_tree import MerkleTree, hash_leaf, hash_nodes


class TestMerkleTree(unittest.TestCase):
    """Merkle树测试类"""

    def test_hash_functions(self):
        """测试叶子节点和内部节点的哈希函数"""
        # 测试叶子节点哈希
        leaf_data = b"test_leaf"
        leaf_hash = hash_leaf(leaf_data)
        self.assertEqual(len(leaf_hash), 64)  # SM3哈希值为64个十六进制字符

        # 测试内部节点哈希
        left_hash = hash_leaf(b"left")
        right_hash = hash_leaf(b"right")
        node_hash = hash_nodes(left_hash, right_hash)
        self.assertEqual(len(node_hash), 64)

        # 测试哈希函数的确定性
        self.assertEqual(hash_leaf(leaf_data), hash_leaf(leaf_data))
        self.assertEqual(hash_nodes(left_hash, right_hash), hash_nodes(left_hash, right_hash))

    def test_empty_tree(self):
        """测试空Merkle树"""
        empty_tree = MerkleTree([])
        self.assertEqual(empty_tree.get_root(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(empty_tree.leaf_count, 0)

    def test_single_leaf_tree(self):
        """测试只有一个叶子节点的Merkle树"""
        leaf_data = b"single_leaf"
        tree = MerkleTree([leaf_data])

        # 根节点应该等于叶子节点的哈希（因为没有其他节点可合并）
        self.assertEqual(tree.get_root(), hash_leaf(leaf_data))

        # 验证存在性证明
        proof, is_right = tree.get_proof(0)
        self.assertTrue(tree.verify_proof(leaf_data, proof, is_right, tree.get_root()))

    def test_small_trees(self):
        """测试小型Merkle树（2^n个叶子节点）"""
        # 测试2个叶子节点
        leaves_2 = [b"leaf0", b"leaf1"]
        tree_2 = MerkleTree(leaves_2)
        self.assertEqual(tree_2.leaf_count, 2)
        self.assertEqual(tree_2.size, 2)
        self.assertEqual(tree_2.height, 1)

        # 验证根节点计算
        expected_root_2 = hash_nodes(hash_leaf(leaves_2[0]), hash_leaf(leaves_2[1]))
        self.assertEqual(tree_2.get_root(), expected_root_2)

        # 测试4个叶子节点
        leaves_4 = [b"a", b"b", b"c", b"d"]
        tree_4 = MerkleTree(leaves_4)
        self.assertEqual(tree_4.leaf_count, 4)
        self.assertEqual(tree_4.size, 4)
        self.assertEqual(tree_4.height, 2)

        # 验证根节点计算
        level1_0 = hash_nodes(hash_leaf(leaves_4[0]), hash_leaf(leaves_4[1]))
        level1_1 = hash_nodes(hash_leaf(leaves_4[2]), hash_leaf(leaves_4[3]))
        expected_root_4 = hash_nodes(level1_0, level1_1)
        self.assertEqual(tree_4.get_root(), expected_root_4)

    def test_non_power_of_two(self):
        """测试叶子节点数不是2的幂的情况"""
        # 3个叶子节点（应填充为4个）
        leaves_3 = [b"x", b"y", b"z"]
        tree_3 = MerkleTree(leaves_3)

        self.assertEqual(tree_3.leaf_count, 3)
        self.assertEqual(tree_3.size, 4)  # 向上取整为2^2=4
        self.assertEqual(tree_3.height, 2)

        # 验证第3个叶子节点的证明（索引2）
        proof, is_right = tree_3.get_proof(2)
        self.assertTrue(tree_3.verify_proof(leaves_3[2], proof, is_right, tree_3.get_root()))

    def test_existence_proof(self):
        """测试存在性证明"""
        leaves = [b"data" + str(i).encode() for i in range(16)]  # 16个叶子节点
        tree = MerkleTree(leaves)

        # 验证每个叶子节点的存在性证明
        for i in range(16):
            proof, is_right = tree.get_proof(i)
            self.assertTrue(
                tree.verify_proof(leaves[i], proof, is_right, tree.get_root()),
                f"索引{i}的存在性证明验证失败"
            )

            # 验证证明长度等于树的高度
            self.assertEqual(len(proof), tree.height)

    def test_invalid_proof(self):
        """测试无效的存在性证明"""
        leaves = [b"a", b"b", b"c", b"d"]
        tree = MerkleTree(leaves)

        # 正确的证明
        proof, is_right = tree.get_proof(0)

        # 篡改数据
        invalid_data = b"a_tampered"
        self.assertFalse(
            tree.verify_proof(invalid_data, proof, is_right, tree.get_root())
        )

        # 篡改证明
        if proof:
            proof[0] = "0" * 64  # 篡改第一个证明节点
            self.assertFalse(
                tree.verify_proof(leaves[0], proof, is_right, tree.get_root())
            )

        # 篡改根哈希
        self.assertFalse(
            tree.verify_proof(leaves[0], proof, is_right, "0" * 64)
        )

    def test_non_existence_proof(self):
        """测试不存在性证明"""
        # 5个叶子节点（填充为8个）
        leaves = [b"0", b"1", b"2", b"3", b"4"]
        tree = MerkleTree(leaves)

        # 测试索引5的不存在性证明（在有效范围内但无数据）
        left_idx, left_proof, left_is_right, right_idx, right_proof, right_is_right = tree.get_non_existence_proof(5)

        # 应该找到左邻居4和右邻居不存在
        self.assertEqual(left_idx, 4)
        self.assertIsNone(right_idx)

        # 验证证明
        left_data = leaves[left_idx] if left_idx is not None else None
        right_data = leaves[right_idx] if right_idx is not None else None

        self.assertTrue(
            tree.verify_non_existence(5, left_data, left_proof, left_is_right,
                                      right_data, right_proof, right_is_right)
        )

        # 测试索引6的不存在性证明
        left_idx, left_proof, left_is_right, right_idx, right_proof, right_is_right = tree.get_non_existence_proof(6)
        self.assertEqual(left_idx, 4)
        self.assertIsNone(right_idx)

        # 测试一个在两个有效节点之间的索引
        leaves = [b"a", b"b", b"d", b"e"]
        tree = MerkleTree(leaves)

        # 证明索引2不存在（假设我们删除了"c"）
        left_idx, left_proof, left_is_right, right_idx, right_proof, right_is_right = tree.get_non_existence_proof(2)
        self.assertEqual(left_idx, 1)  # 左邻居是"b"
        self.assertEqual(right_idx, 2)  # 右邻居是"d"（索引2）

        left_data = leaves[left_idx]
        right_data = leaves[right_idx]

        self.assertTrue(
            tree.verify_non_existence(2, left_data, left_proof, left_is_right,
                                      right_data, right_proof, right_is_right)
        )

    def test_invalid_non_existence(self):
        """测试无效的不存在性证明"""
        leaves = [b"0", b"1", b"2", b"3", b"4"]
        tree = MerkleTree(leaves)

        # 尝试为存在的索引生成不存在性证明
        with self.assertRaises(ValueError):
            tree.get_non_existence_proof(2)  # 索引2存在

        # 获取有效的不存在性证明
        left_idx, left_proof, left_is_right, right_idx, right_proof, right_is_right = tree.get_non_existence_proof(5)

        left_data = leaves[left_idx] if left_idx is not None else None
        right_data = leaves[right_idx] if right_idx is not None else None

        # 篡改左邻居数据
        if left_data is not None:
            invalid_left_data = left_data + b"_tampered"
            self.assertFalse(
                tree.verify_non_existence(5, invalid_left_data, left_proof, left_is_right,
                                          right_data, right_proof, right_is_right)
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
