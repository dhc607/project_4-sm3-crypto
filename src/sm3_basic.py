#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SM3密码哈希算法的基本实现
遵循GB/T 32905-2016《信息安全技术 SM3密码杂凑算法》标准
"""

import struct

# 常量定义
IV = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
]

T = [0x79CC4519] * 16 + [0x7A879D8A] * 48


def rotate_left(x, n):
    """循环左移n位"""
    return ((x << n) & 0xFFFFFFFF) | ((x >> (32 - n)) & 0xFFFFFFFF)


def P0(x):
    """置换函数P0"""
    return x ^ rotate_left(x, 9) ^ rotate_left(x, 17)


def P1(x):
    """置换函数P1"""
    return x ^ rotate_left(x, 15) ^ rotate_left(x, 23)


def FF(x, y, z, j):
    """布尔函数FF"""
    if 0 <= j <= 15:
        return x ^ y ^ z
    else:  # 16 <= j <= 63
        return (x & y) | (x & z) | (y & z)


def GG(x, y, z, j):
    """布尔函数GG"""
    if 0 <= j <= 15:
        return x ^ y ^ z
    else:  # 16 <= j <= 63
        return (x & y) | ((~x) & z)


def padding(message):
    """
    对消息进行填充
    遵循SM3的填充规则：
    1. 首先添加一个'1'位
    2. 然后添加k个'0'位，使得填充后的消息长度模512等于448
    3. 最后添加64位的消息原始长度（以比特为单位）
    """
    # 消息长度（比特）
    message_bit_length = len(message) * 8

    # 添加'1'位
    message += b'\x80'

    # 计算需要填充的'0'的数量
    padding_length = (448 - (len(message) * 8) % 512) // 8
    if padding_length < 0:
        padding_length += 64  # 64字节 = 512比特

    # 添加'0'位
    message += b'\x00' * padding_length

    # 添加原始长度（64位，小端序）
    message += struct.pack('<Q', message_bit_length)

    return message


def message_extension(B):
    """
    消息扩展函数
    将512比特的消息块B扩展为132个字W[0..67]和W'[0..63]
    """
    # 将B拆分为16个字W[0..15]
    W = list(struct.unpack('<16I', B))

    # 扩展生成W[16..67]
    for j in range(16, 68):
        Wj = P1(W[j - 16] ^ W[j - 9] ^ rotate_left(W[j - 3], 15)) ^ rotate_left(W[j - 13], 7) ^ W[j - 6]
        W.append(Wj & 0xFFFFFFFF)  # 确保32位

    # 生成W'[0..63]
    W_prime = []
    for j in range(64):
        W_prime_j = W[j] ^ W[j + 4]
        W_prime.append(W_prime_j & 0xFFFFFFFF)

    return W, W_prime


def compression(V, B):
    """
    压缩函数
    将当前的链接值V和消息块B压缩，生成新的链接值
    """
    # 消息扩展
    W, W_prime = message_extension(B)

    # 初始化工作变量
    A, B, C, D, E, F, G, H = V

    # 64轮迭代
    for j in range(64):
        # 计算T_j
        Tj = T[j]

        # 计算中间变量
        SS1 = rotate_left((rotate_left(A, 12) + E + rotate_left(Tj, j)) & 0xFFFFFFFF, 7)
        SS2 = SS1 ^ rotate_left(A, 12)

        TT1 = (FF(A, B, C, j) + D + SS2 + W_prime[j]) & 0xFFFFFFFF
        TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF

        # 更新工作变量
        D = C
        C = rotate_left(B, 9)
        B = A
        A = TT1
        H = G
        G = rotate_left(F, 19)
        F = E
        E = P0(TT2)

    # 计算新的链接值
    new_V = [
        (A ^ V[0]) & 0xFFFFFFFF,
        (B ^ V[1]) & 0xFFFFFFFF,
        (C ^ V[2]) & 0xFFFFFFFF,
        (D ^ V[3]) & 0xFFFFFFFF,
        (E ^ V[4]) & 0xFFFFFFFF,
        (F ^ V[5]) & 0xFFFFFFFF,
        (G ^ V[6]) & 0xFFFFFFFF,
        (H ^ V[7]) & 0xFFFFFFFF
    ]

    return new_V


def sm3_hash(message):
    """
    计算消息的SM3哈希值
    :param message: 输入消息，bytes类型
    :return: 哈希值，16进制字符串
    """
    # 对消息进行填充
    padded_message = padding(message)

    # 初始化链接值
    V = IV.copy()

    # 处理每个512比特的消息块
    for i in range(0, len(padded_message), 64):  # 64字节 = 512比特
        B = padded_message[i:i + 64]
        V = compression(V, B)

    # 将链接值转换为16进制字符串
    hash_hex = ''.join(f'{x:08x}' for x in V)
    return hash_hex


# 测试函数
def test_sm3():
    """测试SM3哈希函数"""
    # 测试向量1：空消息
    assert sm3_hash(b'') == '1ab21d8355cfa17f8e61194831e81a8f794264c6'

    # 测试向量2："abc"
    assert sm3_hash(b'abc') == '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'

    # 测试向量3："abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
    assert sm3_hash(
        b'abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd') == 'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732'

    print("所有SM3测试通过!")


if __name__ == "__main__":
    test_sm3()
