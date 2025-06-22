def ROLT(x, n):
    """
    将32bit的x循环左移 n bit
    :param x: 32bit数据，十六进制数
    :param n: 循环左移位数，整数
    :return: 32bit数据，十六进制数
    """
    return ((x << n) & 0xffffffff) ^ (x >> (32 - n))


def sha1_padding(msg):
    """
    将明文msg填充至512bit的整数倍
    :param msg: 明文，字节对象（字节串）
    :return: 填充后的明文，十六进制串
    """
    # 将消息编码成二进制串
    bin_text = ''
    EM = ''
    for _ in msg:
        bin_text += bin(_)[2:].zfill(8)
    
    init_len = len(bin_text)

    # 填充
    bin_text += '1'
    bin_len = init_len + 1
    while bin_len % 512 != 448:
        bin_text += '0'
        bin_len += 1
    
    # 将init_len用64位格式补在bin_text最后
    bin_text += bin(init_len)[2:].zfill(64)
    # 将bin_text转为十六进制串EM
    l = len(bin_text)
    for i in range(l // 8):
        EM += hex(int(bin_text[8 * i:8 * i + 8], 2))[2:].zfill(2)
    
    return EM


def sha1_extend(M):
    """
    将16个32bit（即512bit分组）扩展为80个32bit
    :param M: 一个明文分组16*32bit，十六进制串
    :return: 扩展后的分组80*32bit，十六进制串
    """
    # 将M赋给W的前十六个分组
    W = [0] * 80
    for i in range(16):
        W[i] = int(M[8 * i:8 * i + 8], 16)
    
    # 扩充到80个分组
    for i in range(16, 80):
        W[i] = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16]
        W[i] = ROLT(W[i], 1)
    return W


def sha1_f(x, y, z, r):
    """
    根据轮数r，使用不同的逻辑函数
    :param x: 寄存器B，十六进制数
    :param y: 寄存器C，十六进制数
    :param z: 寄存器D，十六进制数
    :param r: 当前轮数，整数
    :return: 逻辑函数，经过逻辑函数计算得到的值
    """
    if r < 20:
        res = (x & y) | ((~x) & z)
    elif r < 40:
        res = x ^ y ^z
    elif r < 60:
        res = (x & y) | (x & z) | (y & z)
    else:
        res = x ^ y ^ z
    return res


def sha1_round(W, H, K):
    """
    轮函数
    :param W: 扩展后的分组80*32bit，十六进制串
    :param H: 5个寄存器的值，列表[5]: 1个寄存器的值，32bit的十六进制数
    :param K: 4常量值，列表[4]: 1个常量值，32bit的十六进制数
    :return: 更新后的5个寄存器的值，列表[5]: 1个寄存器的值，32bit的十六进制数
    """
    a, b, c, d, e = H[0], H[1], H[2], H[3], H[4]
    for j in range(80):
        temp = ROLT(a, 5) + sha1_f(b, c, d, j) + e + W[j] + K[j // 20] 
        e = d
        d = c
        c = ROLT(b, 30)
        b = a
        a = temp % 2 ** 32
        # print('第', j, '轮')
        # print(bin(a), bin(b), bin(c), bin(d), bin(e))
    H[0] = (H[0] + a) % 2 ** 32
    H[1] = (H[1] + b) % 2 ** 32
    H[2] = (H[2] + c) % 2 ** 32
    H[3] = (H[3] + d) % 2 ** 32
    H[4] = (H[4] + e) % 2 ** 32
    
    return H

def sha1_hexdigest(msg):
    """
    计算十六进制的哈希值
    :param msg: 明文，字节对象（字节串）
    :return: 哈希值，十六进制串
    """
    digest = ''  # 用于保存最后的哈希值
    K = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]  # 给定的常量值
    H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]  # 给定的初始寄存器的值

    # 1. 消息填充
    padded_hex = sha1_padding(msg)  # 获取填充后的十六进制字符串

    # 2. 分块处理（每组512bit=128个十六进制字符）
    num_blocks = len(padded_hex) // 128
    for block_idx in range(num_blocks):
        # 提取当前分组（128个十六进制字符）
        block = padded_hex[block_idx * 128: (block_idx + 1) * 128]

        # 3. 扩展分组为80个32bit字
        W = sha1_extend(block)

        # 4. 轮函数处理并更新寄存器
        # 深拷贝当前寄存器状态（避免修改原始H）
        current_H = [h for h in H]
        H = sha1_round(W, current_H, K)

    # 5. 拼接最终哈希值（每个寄存器转8位十六进制）
    for h_val in H:
        digest += f"{h_val:08x}"  # 小写十六进制，固定8位

    return digest
        

def test(msg):
    import hashlib
    print("原始消息：", msg)
    msg = msg.encode()
    print('SHA-1算法输出的哈希值：', sha1_hexdigest(msg))
    # print('hashlib', hashlib.sha1(msg).digest())


if __name__ == '__main__':
    print("-" * 80)
    msg = "School of Cyber Science and Technology"
    test(msg)
    print("-" * 80)
    msg = "SHA-1 算法的输入是长度小于2^64的任意消息X，输出160位的Hash值。"
    test(msg)
    print("-" * 80)
    msg = "在安全应用中使用的Hash函数称为密码学Hash函数。常用的几种密码学Hash函数有MD系列、SHA系列等。安全Hash算法SHA（Security Hash " \
         "Algorithm）是使用最为广泛的Hash函数，由美国标准与技术研究所（NIST）设计，并于1993作为联邦信息处理标准（FIPS 180）发布，该版本称为SHA-0，修订版于1995年发布（FIPS " \
         "180），通常称之为SHA-1，即安全Hash标准。"
    test(msg)
    print("-" * 80)

