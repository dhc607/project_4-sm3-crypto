#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SM3长度扩展攻击测试
验证攻击的正确性和有效性
"""

import unittest
import random
from src.sm3_optimized import sm3_hash_optimized
from src.length_extension import (
    sm3_length_extension_attack,
    verify_length_extension,
    parse_hash
)


class TestLengthExtensionAttack(unittest.TestCase):
    """SM3长度扩展攻击测试类"""

    def test_parse_hash(self):
        """测试哈希值解析功能"""
        # 测试向量：空消息的哈希
        hash_hex = '1ab21d8355cfa17f8e61194831e81a8f794264c6'
        # 补全为64个字符
        hash_hex = hash_hex.ljust(64, '0')

        parsed = parse_hash(hash_hex)
        self.assertEqual(len(parsed), 8)
        self.assertTrue(all(isinstance(x, int) for x in parsed))
        self.assertTrue(all(0 <= x < 2 ** 32 for x in parsed))

    def test_verify_attack_basic(self):
        """测试基本的长度扩展攻击验证"""
        # 测试空消息
        self.assertTrue(verify_length_extension(b'', b"append"))

        # 测试短消息
        self.assertTrue(verify_length_extension(b"secret", b"ext"))

        # 测试刚好一个块的消息（64字节）
        self.assertTrue(verify_length_extension(b"a" * 64, b"more data"))

    def test_attack_results(self):
        """测试攻击结果的正确性"""
        original_msg = b"user=normal&role=user"
        append_data = b"&role=admin"

        # 计算原始消息的哈希
        original_hash = sm3_hash_optimized(original_msg)

        # 执行长度扩展攻击
        attacked_hash, extended_msg = sm3_length_extension_attack(
            original_hash, len(original_msg), append_data
        )

        # 计算原始消息+填充+追加数据的真实哈希
        from src.sm3_basic import padding
        original_padded = padding(original_msg)

    真实_msg = original_padded + append_data
    真实_hash = sm3_hash_optimized(真实_msg)

    # 验证攻击得到的哈希与真实哈希一致
    self.assertEqual(attacked_hash, 真实_hash)

    # 验证扩展消息的结构（前半部分应该是原始消息+填充）
    self.assertEqual(extended_msg[:len(original_padded)], original_padded)
    self.assertEqual(extended_msg[len(original_padded):], append_data)


def test_multiple_block_attack(self):
    """测试跨多个块的长度扩展攻击"""
    # 创建一个需要多个块的长消息
    original_msg = b"base_message_" + b"x" * 200  # 总长度213字节
    append_data = b"_appended_data_" + b"y" * 150  # 追加数据

    # 验证攻击
    self.assertTrue(verify_length_extension(original_msg, append_data))


def test_random_messages_attack(self):
    """测试随机消息的长度扩展攻击"""
    for _ in range(5):
        # 生成随机原始消息
        original_len = random.randint(1, 512)
        original_msg = bytes(random.getrandbits(8) for _ in range(original_len))

        # 生成随机追加数据
        append_len = random.randint(1, 256)
        append_data = bytes(random.getrandbits(8) for _ in range(append_len))

        # 验证攻击
        self.assertTrue(verify_length_extension(original_msg, append_data),
                        "随机消息的长度扩展攻击失败")


if __name__ == "__main__":
    unittest.main(verbosity=2)
