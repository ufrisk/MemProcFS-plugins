# pym_regsecrets.py
#
# Pypykatz RegSecrets plugin for MemProcFs
#
# https://github.com/skelsec/
# https://gist.githubusercontent.com/skelsec/617abdc40a29a60edd337177f5dce85a/raw/b11e456acc23a454bd52e649cc42081c8ddd1b32/gistfile1.txt
#
# (c) Tamas Jos, 2019
# Author: Tamas Jos (@skelsec), info@skelsec.com
#
# adaptation to MemProcFS plugin by:
# (c) Ulf Frisk, 2019-2021
# Author: Ulf Frisk (@UlfFrisk), pcileech@frizk.net
#

import memprocfs
from vmmpyplugin import *
import traceback

# globals needed for FS

is_initialized = False
import_failed = None
parsing_failed = None
result_all = ''
result_sam = ''
result_security = ''
result_software = ''

import_error_text_template = """
The imports for pypykatz plugin have failed at some point.
Common causes:
	1. You dont have pypykatz installed.
	2. You dont have the latest versions of pypykatz and/or aiowinreg.
	2. Python runtime environment used by MemProcFs is not the same as you have installed pypykatz in.
	3. You are not using the correct python version.
	
Error traceback:
%s
"""

parsing_error_template = """
pypykatz plugin tried to parse the registry hives in the memory dump but failed.
This could be caused by multiple things:
	1. The pypykatz's parser code is potato.
	2. MemProcFs could not fully parse the memory, usually this happens with incorrect memory dump files.
		
Error traceback:
%s
"""

import_error_text = None
parsing_error_text = None

try:
	from pypykatz.registry.sam.sam import *
	from pypykatz.registry.security.security import *
	from pypykatz.registry.system.system import *
	from pypykatz.registry.software.software import *
	from aiowinreg.hive import AIOWinRegHive
	from aiowinreg.filestruct.hbin import NTRegistryHbin
	#this needs to be the last line!
	import_failed = False
		
except Exception as e:
	import_failed = True
	if VmmPyPlugin_fPrintV:
		traceback.print_exc()
	import_error_text = import_error_text_template % traceback.format_exc()
	pass
	


class MemProcFS_RegReader:
	"""
	This class provides buffer-like reader interface which can be delegated to AIOWinreg's HIVE classes.
	Emulates reading and seeking capablities of a buffer but actually calling the underlying MemProcFS API. 
	"""
	def __init__(self, hive):
		self.hive = hive
		self.position = 0
		self.firstread = True

	def read(self, count = -1):
		if count < 0:
			raise Exception('Cant read negative count')
		elif count == 0:
			return None
		
		data = self.hive.memory.read(self.position, count, 0)
		self.position += count
		return data
	
	def seek(self, count, whence = 0):
		if whence == 0:
			if count < 0:
				raise Exception('whence 0 requires positive values or 0')
			self.position = count
		elif whence == 1:
			self.position += count
		elif whence == 2:
			raise Exception('Cant seek from the end!')

def list_hives():
	for x in vmm.reg_hive_list():
		yield x



def get_hive(hive_name, hive_name_short):
	for hiveinfo in list_hives():
		if hiveinfo.name.endswith(hive_name):
			return hiveinfo
	for hiveinfo in list_hives():
		if hive_name_short in hiveinfo.name:
			return hiveinfo
	return None



def create_hive(hive_name, hive_name_short):
	hive = get_hive(hive_name, hive_name_short)
	reader = MemProcFS_RegReader(hive)
	hroot = NTRegistryHbin.read(reader)
	reader = MemProcFS_RegReader(hive)
	return AIOWinRegHive(reader, hroot, is_file = False)



def parse_reg():
	global result_all, result_sam, result_security, result_software

	sam_hive = create_hive('SAM-MACHINE_SAM', 'SAM')
	security_hive = create_hive('SECURITY-MACHINE_SECURITY', 'SECURITY')
	system_hive = create_hive('SYSTEM-MACHINE_SYSTEM', 'SYSTEM')
	software_hive = create_hive('SOFTWARE-MACHINE_SOFTWARE', 'SOFTWARE')
	
	if system_hive is None:
		raise Exception('System hive not found! this is mandatory for extracting secrets!')
	system = SYSTEM(system_hive)
	bootkey = system.get_bootkey()
	#input('BootKey: %s' % bootkey.hex())
	
	if sam_hive is not None:
		sam = SAM(sam_hive, bootkey)
		sam.get_secrets()
	else:
		print('SAM hive not found!')
	
	if security_hive is not None:
		security = SECURITY(security_hive, bootkey)
		security.get_secrets()
	else:
		print('SECURITY hive not found!')
	
	if software_hive is not None:
		software = SOFTWARE(software_hive, bootkey)
		software.get_default_logon()
	else:
		print('SOFTWARE hive not found!')

	result_sam = str(sam)
	result_security = str(security)
	result_software = str(software)
	result_all = result_sam + result_security + result_software



def parse_reg_catch():
	global parsing_failed, parsing_error_text

	try:
		parse_reg()
		parsing_failed = False
			
	except Exception as e:
		parsing_failed = True
		if VmmPyPlugin_fPrintV:
			traceback.print_exc()
		parsing_error_text = parsing_error_template % (traceback.format_exc()) 
		pass
		


def ReadResultFile(pid, file_path, file_name, file_attr, bytes_length, bytes_offset):
	"""
	reads the all_results data as file on the virtual FS
	"""
	global result_all, result_sam, result_security, result_software
	
	if file_name == 'all.txt':
		return result_all[bytes_offset:bytes_offset+bytes_length].encode()

	if file_name == 'sam.txt':
		return result_sam[bytes_offset:bytes_offset+bytes_length].encode()

	if file_name == 'security.txt':
		return result_security[bytes_offset:bytes_offset+bytes_length].encode()

	if file_name == 'software.txt':
		return result_software[bytes_offset:bytes_offset+bytes_length].encode()

	return None



def ReadErrors(pid, file_path, file_name, file_attr, bytes_length, bytes_offset):
	try:
			
		if file_name == 'import_error.txt':
			return import_error_text.encode()[bytes_offset:bytes_offset+bytes_length]
		if file_name == 'parsing_error.txt':
			return parsing_error_text.encode()[bytes_offset:bytes_offset+bytes_length]
			
	except Exception as e:
		if VmmPyPlugin_fPrintV:
			traceback.print_exc()
		return None



def List(pid, path):
	#
	# List function - this module employs a dynamic list function - which makes
	# it responsible for providing directory listings of its contents in a
	# highly optimized way. It is very important that the List function is as
	# speedy as possible - to avoid locking up the file system.
	#
	# First check the directory to be listed. Only the module root directory is
	# allowed. If it's not the module root directory return None.
	global is_initialized, import_failed, parsing_failed, import_error_text, parsing_error_text
	global result_all, result_sam, result_security, result_software
	
	try:
			
		if path != 'regsecrets':
			return None

		if is_initialized == False:
			parse_reg_catch()
			is_initialized = True

		if import_failed == True:
			print(import_failed)
			result = {
				'import_error.txt': {'size': len(import_error_text), 'read': ReadErrors, 'write': None},
			}
			return result
		
		if parsing_failed == True:
			result = {
				'parsing_error.txt': {'size': len(parsing_error_text), 'read': ReadErrors, 'write': None},
			}
			return result
		
		if path == 'regsecrets':
			result = {
				'all.txt': {'size': len(result_all), 'read': ReadResultFile, 'write': None},
				'sam.txt': {'size': len(result_sam), 'read': ReadResultFile, 'write': None},
				'security.txt': {'size': len(result_security), 'read': ReadResultFile, 'write': None},
				'software.txt': {'size': len(result_software), 'read': ReadResultFile, 'write': None},
			}
			return result
		
		return None
	
	except Exception as e:
		if VmmPyPlugin_fPrintV:
			traceback.print_exc()
		return None



def Notify(fEvent, bytesData):
	if fEvent == memprocfs.PLUGIN_EVENT_TOTALREFRESH and not import_failed and not parsing_failed:
		global is_initialized
		is_initialized = False



def Initialize(target_system, target_memorymodel):
	# Check that the operating system is 32-bit or 64-bit Windows. If it's not
	# then raise an exception to terminate loading of this module.
	if target_system != memprocfs.SYSTEM_WINDOWS_X64 and target_system != memprocfs.SYSTEM_WINDOWS_X86:
		raise RuntimeError("Only Windows is supported by the pym_regsecrets module.")
	VmmPyPlugin_FileRegisterDirectory(None, 'regsecrets', List)
