#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SM3长度扩展攻击示例
展示如何在实际场景中应用长度扩展攻击
"""


def main():
    print("=== SM3长度扩展攻击示例 ===")
    print("这个示例展示了如何在不知道原始密钥的情况下，扩展哈希值")
    print("场景：假设我们知道HMAC-SM3(key, 'user=normal&role=user')的结果，但不知道key\n")

    # 假设这是我们知道的哈希值（实际中这可能是从某个系统获得的）
    # 注意：在现实场景中，我们不会知道原始密钥，这里只是为了演示
    secret_key = b"supersecretkey"  # 未知的密钥
    original_message = b"user=normal&role=user"  # 已知的消息部分

    # 计算原始的HMAC-SM3哈希（在现实中，我们只能得到这个结果）
    from src.sm3_optimized import sm3_hash_optimized
    original_hash = sm3_hash_optimized(secret_key + original_message)
    print(f"原始哈希值: {original_hash}")
    print(f"原始消息: {original_message.decode()}")
    print(f"密钥长度: {len(secret_key)}字节 (我们不知道这个值，但可以猜测或暴力破解)\n")

    # 我们想要构造一个新的消息，使得其哈希值可以通过长度扩展攻击得到
    # 新消息应该是 "user=normal&role=user" + 填充 + "&role=admin"
    append_data = b"&role=admin"

    # 执行长度扩展攻击
    from src.length_extension import sm3_length_extension_attack
    extended_hash, extended_message = sm3_length_extension_attack(
        original_hash,
        len(secret_key + original_message),  # 原始数据总长度（密钥+消息）
        append_data
    )

    print(f"扩展后哈希值: {extended_hash}")
    print(f"扩展后消息结构: [密钥] + [原始消息] + [填充] + [追加数据]")
    print(f"追加的数据: {append_data.decode()}\n")

    # 验证攻击是否成功
    # 计算真实的扩展消息哈希（仅用于验证，实际中我们无法这样做，因为不知道密钥）


真实_extended_message = secret_key + extended_message[len(secret_key):]
真实_extended_hash = sm3_hash_optimized(真实_extended_message)

print(f"真实扩展哈希值: {真实_extended_hash}")
print(f"攻击是否成功: {'成功' if extended_hash == 真实_extended_hash else '失败'}")

if extended_hash == 真实_extended_hash:
    print("\n这表明，即使不知道原始密钥，我们也能构造出有效的哈希值，"
          "这就是长度扩展攻击的风险所在。")
    print("为了防止此类攻击，应使用HMAC等结构，或限制消息长度。")

if __name__ == "__main__":
    main()
