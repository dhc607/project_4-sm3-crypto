#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SM3哈希算法性能基准测试
比较基本实现和优化实现的性能差异
"""

import time
import random
import matplotlib.pyplot as plt
from src.sm3_basic import sm3_hash
from src.sm3_optimized import sm3_hash_optimized


def benchmark(func, data: bytes, iterations: int = 100) -> float:
    """
    基准测试函数
    :param func: 要测试的哈希函数
    :param data: 输入数据
    :param iterations: 迭代次数
    :return: 平均时间（秒）
    """
    start_time = time.time()
    for _ in range(iterations):
        func(data)
    end_time = time.time()
    return (end_time - start_time) / iterations


def run_benchmarks():
    """运行一系列基准测试"""
    # 测试不同大小的数据
    data_sizes = [16, 64, 256, 1024, 4096, 16384, 65536]  # 字节
    iterations = [1000, 500, 200, 100, 50, 20, 10]  # 不同数据大小的迭代次数

    # 存储结果
    basic_times = []
    optimized_times = []

    print("SM3哈希算法性能基准测试")
    print("========================")
    print(f"{'数据大小(字节)':<15} {'基本实现(ms)':<18} {'优化实现(ms)':<18} {'加速比':<10}")
    print("-" * 65)

    for size, iters in zip(data_sizes, iterations):
        # 生成随机数据
        data = bytes(random.getrandbits(8) for _ in range(size))

        # 测试基本实现
        basic_time = benchmark(sm3_hash, data, iters) * 1000  # 转换为毫秒
        basic_times.append(basic_time)

        # 测试优化实现
        optimized_time = benchmark(sm3_hash_optimized, data, iters) * 1000  # 转换为毫秒
        optimized_times.append(optimized_time)

        # 计算加速比
        speedup = basic_time / optimized_time

        print(f"{size:<15} {basic_time:.4f} {optimized_time:.4f} {speedup:.2f}x")

    # 绘制性能对比图
    plt.figure(figsize=(10, 6))
    x = range(len(data_sizes))

    plt.bar([i - 0.2 for i in x], basic_times, width=0.4, label='基本实现')
    plt.bar([i + 0.2 for i in x], optimized_times, width=0.4, label='优化实现')

    plt.xlabel('数据大小 (字节)')
    plt.ylabel('平均时间 (毫秒)')
    plt.title('SM3哈希算法性能对比')
    plt.xticks(x, data_sizes)
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.7)

    # 保存图表
    plt.tight_layout()
    plt.savefig('sm3_performance_comparison.png')
    print("\n性能对比图表已保存为 'sm3_performance_comparison.png'")

    # 计算总体加速比
    avg_basic = sum(basic_times) / len(basic_times)
    avg_optimized = sum(optimized_times) / len(optimized_times)
    avg_speedup = avg_basic / avg_optimized

    print(f"\n平均加速比: {avg_speedup:.2f}x")


def merkle_tree_benchmark():
    """Merkle树性能基准测试"""
    from src.merkle_tree import MerkleTree

    print("\nMerkle树性能基准测试")
    print("====================")

    # 测试不同大小的Merkle树
    leaf_counts = [1000, 10000, 50000, 100000]

    for count in leaf_counts:
        # 生成叶子节点数据
        leaves = [f"leaf_{i}".encode() for i in range(count)]

        # 测试构建时间
        start_time = time.time()
        tree = MerkleTree(leaves)
        build_time = time.time() - start_time

        # 测试证明生成时间
        proof_times = []
        for i in [0, count // 4, count // 2, 3 * count // 4, count - 1]:
            start = time.time()
            tree.get_proof(i)
            proof_time = (time.time() - start) * 1000  # 转换为毫秒
            proof_times.append(proof_time)

        avg_proof_time = sum(proof_times) / len(proof_times)

        # 测试证明验证时间
        verify_times = []
        for i in [0, count // 4, count // 2, 3 * count // 4, count - 1]:
            proof, is_right = tree.get_proof(i)
            start = time.time()
            tree.verify_proof(leaves[i], proof, is_right, tree.get_root())
            verify_time = (time.time() - start) * 1000  # 转换为毫秒
            verify_times.append(verify_time)

        avg_verify_time = sum(verify_times) / len(verify_times)

        print(f"叶子节点数: {count}")
        print(f"  构建时间: {build_time:.4f}秒")
        print(f"  平均证明生成时间: {avg_proof_time:.4f}毫秒")
        print(f"  平均证明验证时间: {avg_verify_time:.4f}毫秒")
        print(f"  树高度: {tree.height}")
        print(f"  根哈希: {tree.get_root()[:16]}...")
        print("-" * 50)


if __name__ == "__main__":
    run_benchmarks()
    merkle_tree_benchmark()
