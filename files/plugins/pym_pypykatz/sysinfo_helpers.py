# sysinfo_helpers.py
#
# Helper functions to retrieve the file time and version information from a file.
# NB! there are cleaner and better ways to do this, but this works ...
#
# https://github.com/ufrisk/
#
# (c) Ulf Frisk, 2019-2021
# Author: Ulf Frisk, pcileech@frizk.net
#

from io import BytesIO
from dissect import cstruct
import memprocfs

PE_STRUCT_DEFINITIONS = """
    #define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
    #define IMAGE_SIZEOF_SHORT_NAME          8
    typedef struct _IMAGE_DOS_HEADER
    {
        WORD e_magic;
        WORD e_cblp;
        WORD e_cp;
        WORD e_crlc;
        WORD e_cparhdr;
        WORD e_minalloc;
        WORD e_maxalloc;
        WORD e_ss;
        WORD e_sp;
        WORD e_csum;
        WORD e_ip;
        WORD e_cs;
        WORD e_lfarlc;
        WORD e_ovno;
        WORD e_res[4];
        WORD e_oemid;
        WORD e_oeminfo;
        WORD e_res2[10];
        LONG e_lfanew;
    } IMAGE_DOS_HEADER;
    typedef struct _IMAGE_FILE_HEADER {
        WORD  Machine;
        WORD  NumberOfSections;
        DWORD TimeDateStamp;
        DWORD PointerToSymbolTable;
        DWORD NumberOfSymbols;
        WORD  SizeOfOptionalHeader;
        WORD  Characteristics;
    } IMAGE_FILE_HEADER;
"""

def PEGetFileTime(process, module):
    mz_va = process.module(module).base
    mz_bytes = process.memory.read(mz_va, 0x1000)
    mz_stream = BytesIO(mz_bytes)
    # Set up dissect.cstruct
    pestruct = cstruct.cstruct()
    pestruct.load(PE_STRUCT_DEFINITIONS)
    # Parse MZ header
    struct_mz = pestruct.IMAGE_DOS_HEADER(mz_stream)
    if struct_mz.e_magic != 0x5a4d:
        return 0
    mz_stream.seek(struct_mz.e_lfanew)
    signature = pestruct.uint32(mz_stream)
    if signature != 0x4550:
        return 0
    # Parse the PE file_header struct.
    struct_file_header = pestruct.IMAGE_FILE_HEADER(mz_stream)
    return struct_file_header.TimeDateStamp
