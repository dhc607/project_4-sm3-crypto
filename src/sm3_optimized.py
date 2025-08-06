#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SM3密码哈希算法的优化实现
基于基本实现进行了多项性能优化
"""

import struct
from typing import List, bytes

# 常量定义
_IV = (
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
)

# 合并T常量为一个元组，避免重复创建列表
_T = tuple([0x79CC4519] * 16 + [0x7A879D8A] * 48)


def _rotate_left(x: int, n: int) -> int:
    """循环左移n位，优化版本"""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _P0(x: int) -> int:
    """置换函数P0，优化版本"""
    return x ^ _rotate_left(x, 9) ^ _rotate_left(x, 17)


def _P1(x: int) -> int:
    """置换函数P1，优化版本"""
    return x ^ _rotate_left(x, 15) ^ _rotate_left(x, 23)


def _FF1(x: int, y: int, z: int) -> int:
    """FF函数，用于0 <= j <= 15"""
    return x ^ y ^ z


def _FF2(x: int, y: int, z: int) -> int:
    """FF函数，用于16 <= j <= 63"""
    return (x & y) | (x & z) | (y & z)


def _GG1(x: int, y: int, z: int) -> int:
    """GG函数，用于0 <= j <= 15"""
    return x ^ y ^ z


def _GG2(x: int, y: int, z: int) -> int:
    """GG函数，用于16 <= j <= 63"""
    return (x & y) | ((~x) & z)


def _padding(message: bytes) -> bytes:
    """
    对消息进行填充（优化版本）
    减少了不必要的计算和内存操作
    """
    msg_len = len(message)
    # 计算需要填充的字节数
    pad_len = (55 - msg_len) % 64
    # 一次性完成填充
    return (
            message
            + b'\x80'
            + b'\x00' * pad_len
            + struct.pack('<Q', msg_len * 8)
    )


def _message_extension(B: bytes) -> (List[int], List[int]):
    """
    消息扩展函数（优化版本）
    使用预分配列表和局部变量提高访问速度
    """
    # 拆分为16个字W[0..15]
    W = list(struct.unpack('<16I', B))
    W += [0] * 52  # 预分配空间

    # 扩展生成W[16..67]
    for j in range(16, 68):
        val = W[j - 16] ^ W[j - 9]
        val ^= _rotate_left(W[j - 3], 15)
        val = _P1(val)
        val ^= _rotate_left(W[j - 13], 7)
        val ^= W[j - 6]
        W[j] = val & 0xFFFFFFFF

    # 生成W'[0..63]，预分配空间
    W_prime = [0] * 64
    for j in range(64):
        W_prime[j] = W[j] ^ W[j + 4]

    return W, W_prime


def _compression(V: List[int], B: bytes) -> List[int]:
    """
    压缩函数（优化版本）
    使用局部变量减少属性查找开销，合并计算步骤
    """
    # 消息扩展
    W, W_prime = _message_extension(B)

    # 初始化工作变量为局部变量，减少属性访问
    A, B_val, C, D, E, F, G, H = V

    # 预计算旋转值，避免重复计算
    rotate_B = _rotate_left(B_val, 9)
    rotate_F = _rotate_left(F, 19)

    # 64轮迭代
    for j in range(64):
        Tj = _T[j]

        # 根据j选择不同的FF和GG函数
        if j <= 15:
            FF_func = _FF1
            GG_func = _GG1
        else:
            FF_func = _FF2
            GG_func = _GG2

        # 计算中间变量，合并步骤减少临时变量
        SS1 = _rotate_left(
            (_rotate_left(A, 12) + E + _rotate_left(Tj, j)) & 0xFFFFFFFF,
            7
        )
        SS2 = SS1 ^ _rotate_left(A, 12)

        TT1 = (FF_func(A, B_val, C) + D + SS2 + W_prime[j]) & 0xFFFFFFFF
        TT2 = (GG_func(E, F, G) + H + SS1 + W[j]) & 0xFFFFFFFF

        # 更新工作变量
        D, C, B_val, A = C, rotate_B, A, TT1
        H, G, F, E = G, rotate_F, E, _P0(TT2)

        # 预先计算下一轮需要的旋转值
        rotate_B = _rotate_left(B_val, 9)
        rotate_F = _rotate_left(F, 19)

    # 计算新的链接值
    return [
        (A ^ V[0]) & 0xFFFFFFFF,
        (B_val ^ V[1]) & 0xFFFFFFFF,
        (C ^ V[2]) & 0xFFFFFFFF,
        (D ^ V[3]) & 0xFFFFFFFF,
        (E ^ V[4]) & 0xFFFFFFFF,
        (F ^ V[5]) & 0xFFFFFFFF,
        (G ^ V[6]) & 0xFFFFFFFF,
        (H ^ V[7]) & 0xFFFFFFFF
    ]


def sm3_hash_optimized(message: bytes) -> str:
    """
    计算消息的SM3哈希值（优化版本）
    :param message: 输入消息，bytes类型
    :return: 哈希值，16进制字符串
    """
    # 对消息进行填充
    padded_message = _padding(message)

    # 初始化链接值为列表，便于修改
    V = list(_IV)

    # 处理每个512比特的消息块
    for i in range(0, len(padded_message), 64):
        B = padded_message[i:i + 64]
        V = _compression(V, B)

    # 将链接值转换为16进制字符串，使用join优化
    return ''.join(f'{x:08x}' for x in V)


# 测试函数
def test_sm3_optimized():
    """测试优化后的SM3哈希函数"""
    # 测试向量1：空消息
    assert sm3_hash_optimized(b'') == '1ab21d8355cfa17f8e61194831e81a8f794264c6'

    # 测试向量2："abc"
    assert sm3_hash_optimized(b'abc') == '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'

    # 测试向量3：长消息
    long_msg = b'abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd'
    assert sm3_hash_optimized(long_msg) == 'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732'

    print("所有优化版SM3测试通过!")


if __name__ == "__main__":
    test_sm3_optimized()
