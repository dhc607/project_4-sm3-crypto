#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Merkle树使用示例
展示如何构建Merkle树、生成存在性证明和不存在性证明
"""


def main():
    print("=== Merkle树使用示例 ===")

    # 创建一些示例数据
    data = [
        b"Alice", b"Bob", b"Charlie", b"David",
        b"Eve", b"Frank", b"Grace", b"Heidi"
    ]

    print(f"创建包含 {len(data)} 个叶子节点的Merkle树...")
    from src.merkle_tree import MerkleTree
    merkle_tree = MerkleTree(data)

    print(f"Merkle树根哈希: {merkle_tree.get_root()}")
    print(f"Merkle树高度: {merkle_tree.height}")
    print(f"Merkle树大小: {merkle_tree.size} (实际叶子节点数: {merkle_tree.leaf_count})\n")

    # 演示存在性证明
    index = 2  # Charlie的索引
    print(f"=== 存在性证明示例 (索引 {index}: {data[index].decode()}) ===")

    # 获取证明
    proof, is_right = merkle_tree.get_proof(index)
    print(f"证明路径长度: {len(proof)}")
    print("证明路径:")
    for i, (p, ir) in enumerate(zip(proof, is_right)):
        print(f"  第{i + 1}层: {p[:10]}... ({'右侧' if ir else '左侧'})")

    # 验证证明
    valid = merkle_tree.verify_proof(data[index], proof, is_right, merkle_tree.get_root())
    print(f"证明验证结果: {'有效' if valid else '无效'}\n")

    # 演示不存在性证明
    non_existent_index = 8  # 这个索引超出了实际叶子节点范围
    print(f"=== 不存在性证明示例 (索引 {non_existent_index}) ===")

    # 获取不存在性证明
    (left_idx, left_proof, left_is_right,
     right_idx, right_proof, right_is_right) = merkle_tree.get_non_existence_proof(non_existent_index)

    # 显示邻居信息
    if left_idx is not None:
        print(f"左侧最近存在节点: 索引 {left_idx} ({data[left_idx].decode()})")
        print(f"左侧证明长度: {len(left_proof)}")
    if right_idx is not None:
        print(f"右侧最近存在节点: 索引 {right_idx} ({data[right_idx].decode()})")
        print(f"右侧证明长度: {len(right_proof)}")

    # 验证不存在性证明
    left_data = data[left_idx] if left_idx is not None else None
    right_data = data[right_idx] if right_idx is not None else None

    valid = merkle_tree.verify_non_existence(
        non_existent_index,
        left_data, left_proof, left_is_right,
        right_data, right_proof, right_is_right
    )

    print(f"不存在性证明验证结果: {'有效' if valid else '无效'}\n")

    # 演示大型Merkle树
    print("=== 大型Merkle树演示 ===")
    import time

    # 创建10万个叶子节点
    num_leaves = 100000
    print(f"创建包含 {num_leaves} 个叶子节点的大型Merkle树...")

    start_time = time.time()
    large_data = [f"item_{i}".encode() for i in range(num_leaves)]
    large_tree = MerkleTree(large_data)
    build_time = time.time() - start_time

    print(f"大型Merkle树构建完成，耗时: {build_time:.2f}秒")
    print(f"大型Merkle树根哈希: {large_tree.get_root()}")
    print(f"大型Merkle树高度: {large_tree.height}")

    # 测试随机节点的证明
    test_index = 78945
    print(f"\n为索引 {test_index} 生成证明...")

    start_time = time.time()
    proof, is_right = large_tree.get_proof(test_index)
    proof_time = time.time() - start_time

    print(f"证明生成耗时: {proof_time:.4f}秒")
    print(f"证明路径长度: {len(proof)}")

    # 验证证明
    start_time = time.time()
    valid = large_tree.verify_proof(large_data[test_index], proof, is_right, large_tree.get_root())
    verify_time = time.time() - start_time

    print(f"证明验证耗时: {verify_time:.4f}秒")
    print(f"证明验证结果: {'有效' if valid else '无效'}")


if __name__ == "__main__":
    main()
