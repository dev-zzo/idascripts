import idc

def toSigned(v, bits) :
	print "%d/%d" % (v, bits)
	if (v & (1 << (bits - 1))) != 0 :
		return -((~v + 1) & ((1 << bits) - 1))
	return v
#

def getUInt8(ea) :
	return idc.Byte(ea)
#

def getInt8(ea) :
	return toSigned(idc.Byte(ea), 8)
#

def getUInt16(ea) :
	return idc.Word(ea)
#

def getInt16(ea) :
	return toSigned(idc.Word(ea), 16)
#

def getUInt32(ea) :
	return idc.Dword(ea)
#

def getInt32(ea) :
	return toSigned(idc.Dword(ea), 32)
#

def getAsciiz(ea) :
	str = ""
	while idc.Byte(ea) != 0:
		str = str + "%c" % idc.Byte(ea)
		ea += 1
	return str
# End of get_asciiz()

def undefBytes(ea, length) :
	curr = ea
	while curr < ea + length :
		idc.MakeUnkn(curr, 0)
		curr += 1
# End of undefBytes()
