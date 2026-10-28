#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Weixin.dll 自动补丁脚本（多开 + 防撤回）
适用于微信 4.x / Weixin.dll
用法:
    python patch_weixin.py "C:\Program Files\Tencent\Weixin\Weixin.dll"
    python patch_weixin.py Weixin.dll '需放在Weixin.dll同名目录'
    python patch_weixin.py Weixin.dll --no-multi '只防撤回'
    python Patch_Weixin.py Weixin.dll --anti-count 2     只改前 2 处防撤回
    python patch_weixin.py Weixin.dll --no-anti '只多开'
"""

import os
import sys
import shutil
import struct
import re
import bisect
import argparse


# ------------------------- PE 解析 -------------------------

class PE:
    def __init__(self, data):
        self.data = data
        self.sections = []
        self._parse()

    def _parse(self):
        data = self.data
        if data[:2] != b'MZ':
            raise ValueError("不是有效的 PE 文件（缺少 MZ）")
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b'PE\0\0':
            raise ValueError("不是有效的 PE 文件（缺少 PE 签名）")
        coff = e_lfanew + 4
        num_sections = struct.unpack_from('<H', data, coff + 2)[0]
        opt_size = struct.unpack_from('<H', data, coff + 16)[0]
        opt = coff + 20
        sec_table = opt + opt_size

        for i in range(num_sections):
            off = sec_table + i * 40
            name = data[off:off + 8].rstrip(b'\0').decode('ascii', 'ignore')
            vsize = struct.unpack_from('<I', data, off + 8)[0]
            va = struct.unpack_from('<I', data, off + 12)[0]
            raw_size = struct.unpack_from('<I', data, off + 16)[0]
            raw_ptr = struct.unpack_from('<I', data, off + 20)[0]
            self.sections.append({
                'name': name, 'va': va, 'vsize': vsize,
                'raw_size': raw_size, 'raw_ptr': raw_ptr,
            })

    def va_to_off(self, va):
        for s in self.sections:
            size = max(s['vsize'], s['raw_size'])
            if s['va'] <= va < s['va'] + size:
                delta = va - s['va']
                if delta < s['raw_size']:
                    return s['raw_ptr'] + delta
                return None
        return None

    def off_to_va(self, off):
        for s in self.sections:
            if s['raw_ptr'] <= off < s['raw_ptr'] + s['raw_size']:
                return s['va'] + (off - s['raw_ptr'])
        return None


# ------------------------- 模式匹配 -------------------------

def parse_pattern(pattern_str):
    parts = pattern_str.replace('\n', ' ').split()
    pat = bytearray()
    mask = bytearray()
    for p in parts:
        if p in ('??', '?'):
            pat.append(0)
            mask.append(0)
        else:
            pat.append(int(p, 16))
            mask.append(1)
    return bytes(pat), bytes(mask)


def find_pattern(data, pattern_str):
    """用 re 正则加速的 wildcard 搜索，返回所有匹配的文件偏移"""
    pat, mask = parse_pattern(pattern_str)
    parts = []
    for b, m in zip(pat, mask):
        if m:
            parts.append(b'\\x%02x' % b)
        else:
            parts.append(b'.')
    regex = re.compile(b''.join(parts), re.DOTALL)
    return [m.start() for m in regex.finditer(data)]


# ------------------------- 多开补丁 -------------------------

def patch_multi(data, pe):
    """
    多开补丁：
    用 'test cl,cl' (84 C9) 作为锚点，只匹配真正的多开检测函数。
    - 4.2.0.9 函数开头有 push rbp/rsi/rdi/rbx + sub rsp
      从 push 起始处替换 11 字节，保持栈平衡。
    - 老版本无 push，从 sub rsp 替换 7 字节。
    """
    pattern = """
    48 81 EC ?? ?? ?? ??
    48 8D AC 24 ?? ?? ?? ??
    48 C7 85 ?? ?? ?? ?? FE FF FF FF
    84 C9
    """
    matches = find_pattern(data, pattern)
    if not matches:
        print("[!] 多开：未找到特征，可能版本已变化")
        return 0

    count = 0
    for off in matches:
        if off >= 4 and data[off - 4:off] == b'\x55\x56\x57\x53':
            start = off - 4
            replace = bytes([0xB0, 0x01, 0xC3] + [0x90] * 8)
            data[start:start + 11] = replace
            va = pe.off_to_va(start)
            print(f"[+] 多开：已修改 0x{va:X}（含 4 个 push）-> mov al,1; ret; nop...")
        else:
            replace = bytes([0xB0, 0x01, 0xC3, 0x90, 0x90, 0x90, 0x90])
            data[off:off + 7] = replace
            va = pe.off_to_va(off)
            print(f"[+] 多开：已修改 0x{va:X}（无 push）-> mov al,1; ret; nop...")
        count += 1

    if count > 1:
        print(f"[!] 警告：匹配到 {count} 处多开特征，建议用 x64dbg 确认是否都该改")
    return count


# ------------------------- 防撤回补丁 -------------------------

def patch_anti_revoke(data, pe, max_count=None):
    """
    防撤回：
    1. 找 revokemsg 字符串；
    2. 找所有 lea r8, [revokemsg]；
    3. 对每个 lea，向前 0x1000 内找最近的 84 C0 0F 84（test al,al; je）；
    4. 按 VA 排序后，可选只改前 max_count 处；
    5. 把 je 改成 jmp rel32 + nop。
    """
    str_off = data.find(b'revokemsg\x00')
    if str_off == -1:
        print("[!] 防撤回：未找到 revokemsg 字符串")
        return 0
    str_va = pe.off_to_va(str_off)
    if str_va is None:
        print("[!] 防撤回：revokemsg 字符串不在节区中，异常")
        return 0
    print(f"[*] revokemsg 字符串文件偏移=0x{str_off:X}, VA=0x{str_va:X}")

    # 找所有 4C 8D 05 rel32 引用该字符串
    lea_offs = []
    pos = 0
    while True:
        i = data.find(b'\x4C\x8D\x05', pos)
        if i == -1:
            break
        if i + 7 <= len(data):
            rel32 = struct.unpack_from('<i', data, i + 3)[0]
            va = pe.off_to_va(i)
            if va is not None and va + 7 + rel32 == str_va:
                lea_offs.append(i)
        pos = i + 1

    if not lea_offs:
        print("[!] 防撤回：未找到 lea r8, [revokemsg] 引用")
        return 0

    print(f"[*] 找到 {len(lea_offs)} 处 revokemsg 引用")

    # 收集所有 84 C0 0F 84 位置（指向 0F 84）
    test_je_offs = []
    pos = 0
    while True:
        i = data.find(b'\x84\xC0\x0F\x84', pos)
        if i == -1:
            break
        test_je_offs.append(i + 2)
        pos = i + 1

    if not test_je_offs:
        print("[!] 防撤回：未找到 test al,al; je 模式")
        return 0

    # 对每个 lea，向前找最近的 test_je（距离 <= 0x1000）
    je_offs = set()
    for lea_off in lea_offs:
        idx = bisect.bisect_left(test_je_offs, lea_off)
        found = None
        for k in range(idx - 1, -1, -1):
            cand = test_je_offs[k]
            if lea_off - cand <= 0x1000:
                found = cand
                break
            else:
                break
        if found is None:
            va_lea = pe.off_to_va(lea_off)
            print(f"[!] 防撤回：0x{va_lea:X} 上方 0x1000 内未找到 test al,al; je")
            continue
        je_offs.add(found)

    # 按 VA 排序
    je_list = sorted(je_offs, key=lambda o: pe.off_to_va(o) or 0)

    if max_count is not None and max_count > 0 and len(je_list) > max_count:
        print(f"[*] --anti-count {max_count}：只修改前 {max_count} 处（共 {len(je_list)} 处）")
        je_list = je_list[:max_count]

    count = 0
    for je_off in je_list:
        if data[je_off:je_off + 2] != b'\x0F\x84':
            continue
        orig_rel32 = struct.unpack_from('<i', data, je_off + 2)[0]
        je_va = pe.off_to_va(je_off)
        if je_va is None:
            continue
        target = je_va + 6 + orig_rel32
        new_rel32 = target - (je_va + 5)
        new_bytes = b'\xE9' + struct.pack('<i', new_rel32) + b'\x90'
        data[je_off:je_off + 6] = new_bytes
        count += 1
        print(f"[+] 防撤回：0x{je_va:X} je -> jmp 0x{target:X} (rel32=0x{new_rel32 & 0xFFFFFFFF:X})")

    return count


# ------------------------- 主流程 -------------------------

def main():
    parser = argparse.ArgumentParser(description="Weixin.dll 自动补丁（多开 + 防撤回）")
    parser.add_argument("dll", nargs="?", default="Weixin.dll", help="Weixin.dll 路径")
    parser.add_argument("--no-multi", action="store_true", help="不修改多开")
    parser.add_argument("--no-anti", action="store_true", help="不修改防撤回")
    parser.add_argument("--anti-count", type=int, default=None,
                        help="防撤回最多修改前 N 处（默认全部）")
    parser.add_argument("--no-backup", action="store_true", help="不生成 .bak 备份")
    args = parser.parse_args()

    dll_path = args.dll
    if not os.path.isfile(dll_path):
        print(f"[!] 文件不存在: {dll_path}")
        sys.exit(1)

    print(f"[*] 读取: {dll_path}")
    with open(dll_path, "rb") as f:
        original = f.read()

    data = bytearray(original)
    pe = PE(data)

    print(f"[*] 节区数: {len(pe.sections)}")

    total = 0
    if not args.no_multi:
        print("\n===== 多开补丁 =====")
        total += patch_multi(data, pe)

    if not args.no_anti:
        print("\n===== 防撤回补丁 =====")
        total += patch_anti_revoke(data, pe, max_count=args.anti_count)

    if total == 0:
        print("\n[!] 没有发生任何修改，请检查版本或特征码")
        sys.exit(2)

    if not args.no_backup:
        bak = dll_path + ".bak"
        if not os.path.exists(bak):
            shutil.copy2(dll_path, bak)
            print(f"\n[*] 已备份原文件: {bak}")
        else:
            print(f"\n[*] 备份已存在，不覆盖: {bak}")

    with open(dll_path, "wb") as f:
        f.write(data)

    print(f"\n[+] 完成，共修改 {total} 处。")
    print("[*] 建议先测试多开与防撤回；若微信更新导致特征失效，脚本会提示未找到。")


if __name__ == "__main__":
    main()