#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QQNT wrapper.node 自动补丁脚本 (群聊 + 单聊 + 拍一拍 防撤回)
适用版本: QQNT 9.9.x 系列 (基于 9.9.33/9.9.36 特征码)

用法:
    python Patch_QQNT.py "C:\Program Files\Tencent\QQNT\versions\9.9.36-53644\resources\app\wrapper.node"
    python Patch_QQNT.py wrapper.node
    python Patch_QQNT.py wrapper.node --no-group  # 只打单聊和拍一拍
    python Patch_QQNT.py wrapper.node --no-c2c    # 只打群聊和拍一拍
    python Patch_QQNT.py wrapper.node --no-pai    # 只打群聊和单聊
"""

import os
import sys
import shutil
import argparse
import struct

# ------------------------- PE 解析 (获取基址用) -------------------------
class PE:
    def __init__(self, data):
        self.data = data
        self.sections = []
        self._parse()

    def _parse(self):
        data = self.data
        if data[:2] != b'MZ':
            raise ValueError("不是有效的 PE 文件")
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        coff = e_lfanew + 4
        num_sections = struct.unpack_from('<H', data, coff + 2)[0]
        opt_size = struct.unpack_from('<H', data, coff + 16)[0]
        sec_table = coff + 20 + opt_size

        for i in range(num_sections):
            off = sec_table + i * 40
            name = data[off:off+8].rstrip(b'\0').decode('ascii', 'ignore')
            vsize = struct.unpack_from('<I', data, off + 8)[0]
            va = struct.unpack_from('<I', data, off + 12)[0]
            raw_size = struct.unpack_from('<I', data, off + 16)[0]
            raw_ptr = struct.unpack_from('<I', data, off + 20)[0]
            self.sections.append({'name': name, 'va': va, 'raw_ptr': raw_ptr, 'raw_size': raw_size, 'vsize': vsize})

    def off_to_va(self, off):
        for s in self.sections:
            if s['raw_ptr'] <= off < s['raw_ptr'] + s['raw_size']:
                return s['va'] + (off - s['raw_ptr'])
        return 0

# ------------------------- 核心补丁函数 -------------------------

def patch_group_recall(data, pe):
    """群聊防撤回：0F 87 -> 0F 86"""
    # 加长特征码，包含 mov rdx, [rbp+148] 等上下文
    search_bytes = bytes.fromhex('48 8B 95 48 01 00 00 4C 8B 85 50 01 00 00 4C 89 C0 48 29 D0 48 83 F8 07 0F 87')
    replace_last_2 = bytes.fromhex('0F 86')
    
    count = 0
    start = 0
    while True:
        idx = data.find(search_bytes, start)
        if idx == -1:
            break
        patch_idx = idx + len(search_bytes) - 2
        data[patch_idx:patch_idx+2] = replace_last_2
        va = pe.off_to_va(patch_idx)
        print(f"[+] 群聊防撤回：已修改 0x{va:X} (0F 87 -> 0F 86)")
        count += 1
        start = idx + 1
    return count

def patch_c2c_recall(data, pe):
    """单聊防撤回：NOP 掉 E8 及后续 4 字节"""
    search_bytes = bytes.fromhex('48 8B 8D 20 02 00 00 48 8D 95 A0 00 00 00 E8')
    nop_bytes = b'\x90' * 5
    
    count = 0
    start = 0
    while True:
        idx = data.find(search_bytes, start)
        if idx == -1:
            break
        patch_idx = idx + len(search_bytes) - 1
        data[patch_idx:patch_idx+5] = nop_bytes
        va = pe.off_to_va(patch_idx)
        print(f"[+] 单聊防撤回：已修改 0x{va:X} (NOP 核心 Call)")
        count += 1
        start = idx + 1
    return count

def patch_paiyipai_recall(data, pe):
    """拍一拍防撤回：NOP 掉两个分支的 E8 及后续 4 字节"""
    # 加长特征码，加入 mov [rsp+20], rax 等压栈上下文
    search1 = bytes.fromhex('48 89 44 24 20 4C 89 F9 48 89 F2 4D 89 F0 49 89 D9 E8')
    search2 = bytes.fromhex('48 89 44 24 20 48 8D 8D A0 00 00 00 48 89 F2 4D 89 F0 49 89 D9 E8')
    nop_bytes = b'\x90' * 5
    
    count = 0
    for search_bytes in [search1, search2]:
        start = 0
        while True:
            idx = data.find(search_bytes, start)
            if idx == -1:
                break
            patch_idx = idx + len(search_bytes) - 1
            data[patch_idx:patch_idx+5] = nop_bytes
            va = pe.off_to_va(patch_idx)
            print(f"[+] 拍一拍防撤回：已修改 0x{va:X} (NOP 核心 Call)")
            count += 1
            start = idx + 1
    return count

# ------------------------- 主流程 -------------------------

def main():
    parser = argparse.ArgumentParser(description="QQNT wrapper.node 自动打补丁 (精准防撤回)")
    parser.add_argument("node", nargs="?", default="wrapper.node", help="wrapper.node 路径")
    
    # 可选补丁开关
    parser.add_argument("--no-group", action="store_true", help="不修改群聊防撤回")
    parser.add_argument("--no-c2c", action="store_true", help="不修改单聊防撤回")
    parser.add_argument("--no-pai", action="store_true", help="不修改拍一拍防撤回")
    
    # 其他选项
    parser.add_argument("--no-backup", action="store_true", help="不生成 .bak 备份")
    
    args = parser.parse_args()

    dll_path = args.node
    if not os.path.isfile(dll_path):
        print(f"[!] 文件不存在: {dll_path}")
        sys.exit(1)

    print(f"[*] 正在读取: {dll_path}")
    with open(dll_path, "rb") as f:
        original = f.read()

    data = bytearray(original)
    pe = PE(data)

    total = 0
    
    # 1. 群聊防撤回
    if not args.no_group:
        print("\n===== 群聊防撤回 =====")
        c = patch_group_recall(data, pe)
        if c == 0: 
            print("[!] 未找到特征")
        elif c > 1: 
            print(f"[!] 警告：匹配到 {c} 处群聊特征，可能包含误判！")
        total += c
    else:
        print("\n[-] 已跳过：群聊防撤回")

    # 2. 单聊防撤回
    if not args.no_c2c:
        print("\n===== 单聊防撤回 =====")
        c = patch_c2c_recall(data, pe)
        if c == 0: 
            print("[!] 未找到特征")
        elif c > 1: 
            print(f"[!] 警告：匹配到 {c} 处单聊特征，可能包含误判！")
        total += c
    else:
        print("\n[-] 已跳过：单聊防撤回")

    # 3. 拍一拍防撤回
    if not args.no_pai:
        print("\n===== 拍一拍防撤回 =====")
        c = patch_paiyipai_recall(data, pe)
        if c == 0: 
            print("[!] 未找到特征")
        # 拍一拍正常应该是 2 个（群聊+单聊分支）
        elif c > 2: 
            print(f"[!] 警告：匹配到 {c} 处拍一拍特征，可能包含误判！")
        total += c
    else:
        print("\n[-] 已跳过：拍一拍防撤回")

    # 总结
    if total == 0:
        print("\n[-] 没有发生任何修改。")
        sys.exit(2)

    # 备份原文件
    if not args.no_backup:
        bak = dll_path + ".bak"
        if not os.path.exists(bak):
            shutil.copy2(dll_path, bak)
            print(f"\n[*] 已备份原文件: {bak}")

    # 写入修改
    with open(dll_path, "wb") as f:
        f.write(data)

    print(f"\n[+] 完成！共精准修改 {total} 处。重启 QQ 即可生效。")

if __name__ == "__main__":
    main()