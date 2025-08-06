# SM3密码哈希算法的软件实现与优化

本项目实现了国密标准SM3密码哈希算法，并完成了算法优化、长度扩展攻击验证和Merkle树构建三个主要任务。

## 项目概述

SM3是中国国家密码管理局发布的密码杂凑算法标准（GB/T 32905-2016），适用于数字签名、消息认证、数据完整性校验等场景。本项目包含：

1. SM3算法的基本实现与优化版本
2. 基于SM3的长度扩展攻击验证
3. 基于SM3和RFC6962标准的Merkle树实现，支持10万叶子节点
4. 叶子节点的存在性证明和不存在性证明实现

所有代码均使用Python编写，结构清晰，包含详细注释和完整测试。

## 环境要求

- Python 3.7+

## 安装与使用

1. 克隆仓库到本地
2. 无需安装额外依赖（使用Python标准库）
3. 直接运行各模块或测试

## 运行测试
# 运行SM3测试
python -m unittest tests/test_sm3.py -v

# 运行长度扩展攻击测试
python -m unittest tests/test_attack.py -v

# 运行Merkle树测试
python -m unittest tests/test_merkle.py -v
## 运行示例
# 长度扩展攻击示例
python examples/example_attack.py

# Merkle树示例
python examples/example_merkle.py

# 性能测试
python benchmarks/benchmark.py

