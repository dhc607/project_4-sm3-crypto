#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SM3哈希算法测试
验证基本实现和优化实现的正确性和一致性
"""

import unittest
import random
from src.sm3_basic import sm3_hash
from src.sm3_optimized import sm3_hash_optimized


class TestSM3(unittest.TestCase):
    """SM3哈希算法测试类"""

    def test_empty_message(self):
        """测试空消息的哈希值"""
        expected = '1ab21d8355cfa17f8e61194831e81a8f794264c6'
        self.assertEqual(sm3_hash(b''), expected)
        self.assertEqual(sm3_hash_optimized(b''), expected)

    def test_abc(self):
        """测试消息"abc"的哈希值"""
        expected = '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'
        self.assertEqual(sm3_hash(b'abc'), expected)
        self.assertEqual(sm3_hash_optimized(b'abc'), expected)

    def test_long_message(self):
        """测试长消息的哈希值"""
        msg = b'abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd'
        expected = 'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732'
        self.assertEqual(sm3_hash(msg), expected)
        self.assertEqual(sm3_hash_optimized(msg), expected)

    def test_different_lengths(self):
        """测试不同长度消息的哈希值"""
        # 测试1字节到64字节的消息
        for length in range(1, 65):
            msg = b'a' * length
            # 验证基本实现和优化实现的一致性
            self.assertEqual(
                sm3_hash(msg),
                sm3_hash_optimized(msg),
                f"长度为{length}的消息哈希不一致"
            )

    def test_random_messages(self):
        """测试随机消息的哈希值"""
        # 生成10个随机长度的随机消息
        for _ in range(10):
            length = random.randint(1, 1024)
            msg = bytes(random.getrandbits(8) for _ in range(length))
            # 验证基本实现和优化实现的一致性
            self.assertEqual(
                sm3_hash(msg),
                sm3_hash_optimized(msg),
                f"随机消息（长度{length}）哈希不一致"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
