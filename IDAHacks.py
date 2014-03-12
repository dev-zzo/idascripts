import idc

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
