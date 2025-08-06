#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SM3长度扩展攻击实现
验证SM3算法容易受到长度扩展攻击
"""

import struct
from src.sm3_optimized import (
    _padding, _compression, _message_extension,
    _rotate_left, _P0, _P1, _FF1, _FF2, _GG1, _GG2, _T
)


def parse_hash(hash_hex: str) -> list:
    """
    将SM3哈希值（16进制字符串）解析为初始向量V
    :param hash_hex: SM3哈希值，16进制字符串
    :return: 初始向量V，包含8个32位整数
    """
    if len(hash_hex) != 64:
        raise ValueError("无效的SM3哈希值，长度必须为64个字符")

    V = []
    for i in range(8):
        # 每个字32位，对应8个十六进制字符
        V.append(int(hash_hex[i * 8:(i + 1) * 8], 16))

    return V


def sm3_length_extension_attack(original_hash: str, original_length: int, append_data: bytes) -> (str, bytes):
    """
    SM3长度扩展攻击
    在不知道原始消息的情况下，对原始消息的哈希值进行扩展

    :param original_hash: 原始消息的哈希值
    :param original_length: 原始消息的长度（字节）
    :param append_data: 要追加的数据
    :return: (扩展后的哈希值, 扩展后的消息)
    """
    # 解析原始哈希值为初始向量
    V = parse_hash(original_hash)

    # 计算原始消息填充后的长度
    original_padded_length = original_length + 1  # 添加的'1'位
    pad_zero_length = (55 - original_length) % 64  # 填充的'0'位长度
    original_padded_length += pad_zero_length + 8  # 加上长度字段的8字节

    # 构造扩展消息：原始消息的填充 + 要追加的数据
    # 我们不需要知道原始消息，只需要知道其长度来计算填充
    # 这里构造的是"原始消息填充后 + append_data"的等价表示
    extended_message = b'X' * original_length + _padding(b'X' * original_length)[original_length:] + append_data

    # 对追加的数据进行填充（作为新的消息块）
    # 注意：我们只需要处理追加的数据，因为原始消息的填充已经被考虑
    # 计算追加数据的填充
    append_padded = _padding(append_data)

    # 将追加的数据分块处理
    current_V = V
    # 从原始消息填充后的长度开始处理
    for i in range(0, len(append_padded), 64):
        B = append_padded[i:i + 64]
        current_V = _compression(current_V, B)

    # 计算扩展后的哈希值
    extended_hash = ''.join(f'{x:08x}' for x in current_V)

    return extended_hash, extended_message


def verify_length_extension(original_msg: bytes, append_data: bytes) -> bool:
    """
    验证长度扩展攻击的正确性
    :param original_msg: 原始消息
    :param append_data: 要追加的数据
    :return: 攻击是否成功
    """
    from src.sm3_optimized import sm3_hash_optimized

    # 计算原始消息的哈希
    original_hash = sm3_hash_optimized(original_msg)

    # 执行长度扩展攻击
    attacked_hash, _ = sm3_length_extension_attack(original_hash, len(original_msg), append_data)

    # 计算原始消息 + 填充 + 追加数据的真实哈希
    original_padded = _padding(original_msg)
    extended_msg = original_padded + append_data


real_hash = sm3_hash_optimized(extended_msg)

# 比较攻击得到的哈希和真实哈希
return attacked_hash == 真实_hash


# 测试函数
def test_length_extension():
    """测试长度扩展攻击"""
    # 测试1：简单消息
    original_msg = b"secret_key="
    append_data = b"&user=admin&role=admin"

    result = verify_length_extension(original_msg, append_data)
    assert result, "长度扩展攻击测试1失败"

    # 测试2：不同长度的消息
    test_cases = [
        (b"", b"append"),
        (b"a", b"b"),
        (b"short message", b"appended data"),
        (b"a" * 64, b"extended data"),  # 刚好一个块
        (b"a" * 100, b"more data to append")
    ]

    for i, (msg, append) in enumerate(test_cases):
        result = verify_length_extension(msg, append)
        assert result, f"长度扩展攻击测试{i + 2}失败"

    print("所有长度扩展攻击测试通过!")


if __name__ == "__main__":
    test_length_extension()
