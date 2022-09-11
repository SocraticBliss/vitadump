#!/usr/bin/env python3
# Butchered by SocraticBliss

import os.path
import struct

import idaapi
import idc
from idautils import *

INFO_SIZE = 0x5c
NAME_OFF = 4
NAME_LEN = 27
ENT_TOP_OFF = 0x24
ENT_END_OFF = 0x28
STUB_TOP_OFF = 0x2c
STUB_END_OFF = 0x30

EXPORT_NUM_FUNCS_OFF = 0x6
EXPORT_NID_OFF = 0x10
EXPORT_LIBNAME_OFF = 0x14
EXPORT_NID_TABLE_OFF = 0x18
EXPORT_ENTRY_TABLE_OFF = 0x1c

IMPORT_NUM_FUNCS_OFF = 0x6
IMPORT_LIBNAME_OFF = 0x14
IMPORT_LIBNAME_OFF2 = 0x10
IMPORT_NID_TABLE_OFF = 0x1c
IMPORT_NID_TABLE_OFF2 = 0x14
IMPORT_ENTRY_TABLE_OFF = 0x20
IMPORT_ENTRY_TABLE_OFF2 = 0x18

NORETURN_FUNCS = [0xB997493D, 0x391B5B74, 0x00CCE39C, 0x37691BF8, 0x2f2c6046]


def u32(bytes, start=0):
    return struct.unpack('<I', bytes[start:start + 4])[0]


def u16(bytes, start=0):
    return struct.unpack('<H', bytes[start:start + 2])[0]


def u8(bytes, start=0):
    return struct.unpack('<B', bytes[start:start + 1])[0]


def read_cstring(addr, max_len=0):
    s = ''
    ea = addr
    while True:
        c = idaapi.get_wide_byte(ea)
        if c == 0:
            break
        ea += 1
        s += chr(c)
        if max_len and len(s) > max_len:
            break
    return s


def chunk(s, l):
    '''
        Chunks S into strings of length L, for example:
        >>> chunk('abcd', 2)
        ['ab', 'cd']
        >>> chunk('abcde', 2)
        ['ab', 'cd', 'e']
    '''
    return [s[i:i + l] for i in range(0, len(s), l)]


nid_table = dict()

def load_nids(filename):
    if not os.path.exists(filename):
        print('# Cannot find nids.txt, NIDs won\'t be resolved')
        return
    fin = open(filename, 'r')
    for line in fin.readlines():
        line = line.split()
        nid_table[int(line[0], 16)] = line[1]
    fin.close()
    print('# Loaded {} NIDs'.format(len(nid_table)))


def resolve_nid(nid):
    if nid in nid_table:
        return nid_table[nid]
    return ''


used_names = dict()

def rename_function(ea, name, suffix):
    '''
        Renames a function, optionally adding a _XX suffix to make sure
        all names are unique.
    '''
    name = name + suffix
    if name in used_names:
        used_names[name] += 1
        name += '_{}'.format(used_names[name])
    else:
        used_names[name] = 0
    
    idaapi.set_name(ea, name, SN_CHECK)


def process_nid_table(nid_table_addr, entry_table_addr, num_funcs, libname, name_suffix=''):
    if num_funcs == 0:
        return
    
    nids = idaapi.get_bytes(nid_table_addr, 4 * num_funcs)
    funcs = idaapi.get_bytes(entry_table_addr, 4 * num_funcs)
    
    if not nids or not funcs:
        print('NID table at 0x{0:x} is not supported, bailing out!'.format(nid_table_addr))
        return
    
    for nid, func in zip(chunk(nids, 4), chunk(funcs, 4)):
        nid = u32(nid)
        func = u32(func)
        #print('# nid {} => func {}'.format(hex(nid), hex(func)))
        t_reg = func & 1  # 0 = ARM, 1 = THUMB
        func -= t_reg
        for i in range(4):
            idc.split_sreg_range(func + i, 'T', t_reg, SR_user)
        idaapi.add_func(func, BADADDR)
        
        actual_name = name = resolve_nid(nid)
        if not name:
            name = '{}_{:08X}'.format(libname, nid)
        
        rename_function(func, name, name_suffix)
        
        if nid in NORETURN_FUNCS:
            idc.set_func_attr(func, FUNCATTR_FLAGS, FUNC_NORET)
        
        # add a comment to mangled functions with demangled name, but only for imports
        # or otherwise when ida wouldn't do it itself because of non empty suffix
        '''
        if actual_name.startswith('_Z') and name_suffix:
            demangled = Demangle(actual_name, idaapi.get_inf_attr(INF_LONG_DN))
            if demangled != '':
                SetFunctionCmt(func, demangled, 1)
        '''

def process_export(exp, libname):
    num_funcs = u16(exp, EXPORT_NUM_FUNCS_OFF)
    nid_table = u32(exp, EXPORT_NID_TABLE_OFF)
    entry_table = u32(exp, EXPORT_ENTRY_TABLE_OFF)
    libname_addr = u32(exp, EXPORT_LIBNAME_OFF)
    nid = u32(exp, EXPORT_NID_OFF)
    libname = ''
    if libname_addr:
        libname = read_cstring(libname_addr, 255)
    
    #print('# {} with NID 0x{:x}'.format(libname, nid))
    
    #print('num_funcs: 0x%X' % num_funcs)
    
    process_nid_table(nid_table, entry_table, num_funcs, libname)


def process_import(imp):
    num_funcs = u16(imp, IMPORT_NUM_FUNCS_OFF)
    nid_table = u32(imp, IMPORT_NID_TABLE_OFF if len(imp) == 0x34 else IMPORT_NID_TABLE_OFF2)
    entry_table = u32(imp, IMPORT_ENTRY_TABLE_OFF if len(imp) == 0x34 else IMPORT_ENTRY_TABLE_OFF2)
    libname_addr = u32(imp, IMPORT_LIBNAME_OFF if len(imp) == 0x34 else IMPORT_LIBNAME_OFF2)
    
    if not libname_addr:
        return
    
    #print('num_funcs: 0x%X' % num_funcs)
    
    libname = read_cstring(libname_addr, 255)
    process_nid_table(nid_table, entry_table, num_funcs, libname, '_imp_')

modules = []

def process_module(module_info_addr):
    module_info = idaapi.get_bytes(module_info_addr, INFO_SIZE)
    name = module_info[NAME_OFF:NAME_OFF+NAME_LEN].strip(b'\x00').decode()
    ent_top = u32(module_info, ENT_TOP_OFF)
    ent_end = u32(module_info, ENT_END_OFF)
    ent_len = ent_end - ent_top
    stub_top = u32(module_info, STUB_TOP_OFF)
    stub_end = u32(module_info, STUB_END_OFF)
    stub_len = stub_end - stub_top
    
    #if name == 'SceClockgen' or name == 'SceCtrl' or name == 'SceSblFwLoader' or name == 'SceUsbstorDriver' or name == 'SceUsbd':
        #return
    
    if name not in modules and ent_top < idc.get_segm_end(0):
        print('# Module {} {}'.format(name, hex(module_info_addr)))
        modules.append(name)
        #print('# ent_top:  0x%X' % ent_top)
        #print('# stub_top: 0x%X' % stub_top)
        
        exports = []
        addr = ent_top
        while addr < ent_end:
            size = u16(idc.get_bytes(addr, 2))
            if size == 0:
                break
            #print('export | addr: 0x%X size: 0x%X' % (addr, size))
            exports.append((addr, size))
            addr += size
        
        imports = []
        addr = stub_top
        while addr < stub_end:
            size = u16(idc.get_bytes(addr, 2))
            if size == 0:
                break
            #print('import | addr: 0x%X size: 0x%X' % (addr, size))
            imports.append((addr, size))
            addr += size
        
        # We need to process imports first so that noreturn functions are found
        for (addr, size) in imports:
            process_import(idaapi.get_bytes(addr, size))
        for (addr, size) in exports:
            process_export(idaapi.get_bytes(addr, size), name)


def find_modules_with_string(haystack, off):
    ea = 0
    #c = ' '.join(chunk(haystack, 2))
    while ea != BADADDR:
        ea = idaapi.find_binary(ea, BADADDR, haystack, 0x10, SEARCH_DOWN | SEARCH_CASE)
        if ea != BADADDR:
            process_module(ea + off)
        ea = idaapi.next_addr(ea)


def find_modules():
    module_heur = [
        ('00 00 01 53 63 65', -1), # \x00\x00\x01Sce
        ('00 01 01 53 63 65', -1), # \x00\x01\x01Sce
        ('00 02 01 53 63 65', -1), # \x00\x02\x01Sce
        ('00 06 01 53 63 65', -1), # \x00\x06\x01Sce
        ('00 00 00 55 6E 69 74 79 50 6C 61 79 65 72', -1), # \x00\x00\x00UnityPlayer
    ]
    for haystack, off in module_heur:
        find_modules_with_string(haystack, off)


def find_strings():
    seg_start = seg_end = 0
    
    while seg_start != BADADDR:
        seg_start = idc.get_next_seg(seg_start)
        
        try:
            seg_end = idc.get_segm_end(seg_start)
        except AssertionError:
            continue
        
        bytes = idaapi.get_bytes(seg_start, seg_end - seg_start)
        
        if not bytes:
            continue
        
        start = 0
        while start < len(bytes):
            end = start
            while end < len(bytes) and bytes[end] >= 0x20 and bytes[end] <= 0x7e:
                end += 1
            if end - start > 8 and not idaapi.is_code(idaapi.get_full_flags(seg_start + start)):
                idaapi.create_strlit(seg_start + start, 0, idaapi.inf_get_strtype())
            start = end + 1


def is_reg_call_safe(reg):
    if reg[0] == 'R':
        return int(reg[1:]) > 3
    else:
        return reg in ['LR', 'SP']


def add_xrefs():
    '''
        Searches for MOV / MOVT pair, probably separated by few instructions,
        and adds xrefs to things that look like addresses
    '''
    addr = 0
    while addr != BADADDR:
        addr = idc.next_head(addr)
        if idaapi.print_insn_mnem(addr) == 'MOV':
            reg = idaapi.print_operand(addr, 0)
            if idaapi.print_operand(addr, 1)[0] != '#':
                continue
            val = idaapi.get_operand_value(addr, 1)
            found = False
            next_addr = addr
            for x in range(16): # next 16 instructions
                next_addr = idc.next_head(next_addr)
                if idaapi.print_insn_mnem(next_addr) in ['B', 'BX', 'BL', 'BLX'] and not is_reg_call_safe(reg):
                    break
                if idaapi.print_insn_mnem(next_addr) == 'MOVT' and idaapi.print_operand(next_addr, 0) == reg:
                    if idaapi.print_operand(next_addr, 1)[0] == '#':
                        found = True
                        val += idc.get_operand_value(next_addr, 1) * (2 ** 16)
                    break
                if idaapi.print_operand(next_addr, 0) == reg or idaapi.print_operand(next_addr, 1) == reg:
                    break
            if val & 0xFFFF0000 == 0:
                continue
            if found:
                # pair of MOV/MOVT
                idaapi.op_offset(addr, 1, REF_LOW16, val, 0, 0)
                idaapi.op_offset(next_addr, 1, REF_HIGH16, val, 0, 0)
            else:
                # a single MOV instruction
                idaapi.op_plain_offset(addr, 1, 0)


def remove_chunks(ea):
    '''
        Remove chunks from imported functions because they make no sense.
    '''
    chunks = list(Chunks(ea))
    if len(chunks) > 1:
        for chunk in chunks:
            if chunk[0] != ea:
                RemoveFchunk(ea, chunk[0])
                idaapi.add_func(chunk[0], BADADDR)
        idaapi.auto_wait()


def resolve_local_nids():
    '''
        Finds resolved imported functions and renames them to actual names,
        if the module that provides that function is available and loaded.
        Only works for user-level imports.
    '''
    ea = idaapi.get_next_func(idaapi.next_addr(0)).start_ea
    while ea != BADADDR:
        next = idc.next_head(ea)
        if idaapi.print_insn_mnem(ea) == 'MOV' and idaapi.print_insn_mnem(next) == 'BX' and idaapi.print_operand(ea, 0) == 'R12':
            remove_chunks(ea)
            faddr = idc.get_operand_value(ea, 1) & 0xFFFFFFFE
            actual_name = idaapi.get_func_name(faddr)
            if actual_name and not actual_name.startswith('sub_'):
                rename_function(ea, actual_name, '_imp')
        try:
            ea = idaapi.get_next_func(ea).start_ea
        except:
             break


def main():
    path = os.path.dirname(os.path.realpath(__file__))
    print('# Loading NIDs...')
    load_nids(os.path.join(path, 'nids.txt'))
    print('# Finding modules...')
    find_modules()
    idaapi.auto_wait()
    print('# Finding strings...')
    find_strings()
    print('# Adding xrefs...')
    add_xrefs()
    print('# Resolving local NIDs...')
    resolve_local_nids()
    print('# Done!')


if __name__ == '__main__':
    main()
