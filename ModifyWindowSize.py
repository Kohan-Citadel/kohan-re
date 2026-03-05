#Patches hard-coded window dimensions in _ag.exe to allow for widescreen window layout
#@author sceadu37
#@category Kohan
#@keybinding Ctrl-Alt-M
#@menupath a
#@toolbar
#@runtime PyGhidra

#import ghidra.app.plugin.assembler.GenericAssembler as GenericAssembler
import ghidra.app.plugin.assembler.Assemblers as Assemblers
from ghidra.program.flatapi import FlatProgramAPI
#import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns as AssemblyResolvedPatterns

def getWindowSize():
    width = askInt("Enter Window Width", "Width")
    height = askInt("Enter Window Height", "Height")
    return (width, height)

"""
patches a constant operand at the given location to the given value
"""
def patchConst(address, target_value, new_value):
    ins = getInstructionAt(address)
    #sep = ins.getSeparator(op_index)
    #str_arr = ins.toString().split(' ' if sep is None else sep)
    #patch_index = op_index + 1 if sep is None else op_index
    #print(f"patching [{str_arr[patch_index]}] at address {address}, index {patch_index} from {str_arr}")
    
    #str_arr[patch_index] = str(value)
    #new_ins = (' ' if sep is None else sep).join(str_arr)
    #print(f"new instruction is [{new_ins}]")
    
    parsed_bytes = ins.getParsedBytes()
    byte_value = target_value.to_bytes(2, byteorder="little")
    print(f"target value: {byte_value}")
    for b in parsed_bytes:
        print(f"{(b & 0xFF):02x}", end=' ')
    print("")
    patch_idx = 0
    for patch_idx in range(len(parsed_bytes)):
        for j in range(2):
            print(f"\tcomparing {parsed_bytes[patch_idx+j]&0xFF:02x} to {byte_value[j]:02x}...", end="")
            if (parsed_bytes[patch_idx+j]&0xFF) != byte_value[j]:
                print("no match :(")
                break
            else:
                print("matched!")
        else:
            break
    else:
        print("failed to find matching bytes!")
        raise IndexError
    
    print(f"{address} patching should start at byte {patch_idx} with value {parsed_bytes[patch_idx]&0xff:02x}\n")
    
    flat_prog_api = FlatProgramAPI(currentProgram)
    flat_prog_api.clearListing(address)
    mem = currentProgram.getMemory()
    mem.setBytes(address.add(patch_idx), new_value.to_bytes(2, byteorder="little"))
    disassemble(address)
    
    
    
    #asm = Assemblers.getAssembler(currentProgram)
    #patternBlock = asm.getContextAt(address)
    #parseResults = asm.parseLine(new_ins)
    #print(type(parseResults))
    #for parseRes in parseResults:
    #    print(f"parseRes: {parseRes}")
    #    resolutionResults = asm.resolveTree(parseRes, address, patternBlock)
    #    resolutions =  resolutionResults.getResolutions()
    #    for res in resolutions:
    #        print(f"\tresolution: {res}")
    
    
    
    #asm.assemble(address, new_ins)
    

"""
patches all instances of the given equate to the given value,
then updates the equate to the new value
"""
def patchEquate(equate_name, new_value):
    equateTable = currentProgram.getEquateTable()
    equate = equateTable.getEquate(equate_name)
    target_value = equate.getValue()
    if target_value == new_value:
        return
    equate.renameEquate(equate_name + "_OLD")
    new_equate = equateTable.createEquate(equate_name, new_value)
    
    refs = equate.getReferences()
    for ref in refs:
        addr = ref.getAddress()
        op_idx = ref.getOpIndex()
        patchConst(addr, target_value, new_value)
        new_equate.addReference(addr, op_idx)
    
    equateTable.removeEquate(equate.toString())


if currentProgram is None:
    popup("currentProgram is None!")
else:
    (width, height,) = getWindowSize()
    patchEquate("MAX_HEIGHT", height)
    patchEquate("MAX_HEIGHT_0", height-1)
    patchEquate("MAX_WIDTH", width)
    patchEquate("MAX_WIDTH_0", width-1)
