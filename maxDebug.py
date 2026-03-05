#TODO write a description for this script
#@author 
#@category Kohan
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra


#TODO Add User Code Here

from ghidra.program.model.address import Address
from ghidra.program.model.listing import Listing
from ghidra.program.flatapi import FlatProgramAPI
from jpype.types import *

def patchGlobalDebugLevel():
    byte_list = JByte[:]@[0xB8-0xFF, 0x00, 0x00, 0x00, 0x00, 0x68, 0x3C, 0x2F, 0x59, 0x00, 0x50, 0x90-0xFF, 0x90-0xFF, 0x90-0xFF]
    mem = currentProgram.getMemory()
    flat_prog_api = FlatProgramAPI(currentProgram)
    functionManager = currentProgram.getFunctionManager();
    funcs = functionManager.getFunctions(True)
    for func in funcs:
        if func.getName() == "set_debug_level":
            entry_point = func.getEntryPoint()
            start_addr = entry_point.add(3)
            #addr = Address.getNewAddress(JLong@500000000)
            flat_prog_api.clearListing(start_addr, start_addr.add(len(byte_list)))
            mem.setBytes(start_addr, byte_list)
            disassemble(entry_point)
            
            data_addr = entry_point.getAddress("00592928")
            mem.setInt(data_addr, 0)
patchGlobalDebugLevel()