import idc
import IDAHacks
import RttiError
IDAHacks = reload(IDAHacks)
RttiError = reload(RttiError)

class TypeDescriptor :
	"""
	"""
	
	def __init__(self, rtti, ea) :
		"""
		Construct the TypeDescriptor object from the information at the given EA.
		"""
		
		self.ea = ea
		
		# const void *pVFTable;
		# void *spare;
		# char name[];
		
		self.vtblAddress = idc.Dword(ea)
		name = IDAHacks.getAsciiz(ea + 8) # FIXME: 64-bit
		if name[:4] != ".?AV":
			raise RttiError.RttiError("TypeDescriptor.name does not start with '.?AV'.")
		if name[-2:] != "@@":
			raise RttiError.RttiError("TypeDescriptor.name does not end with '@@'.")
		# Cut extra chars: ".?AV" and "@@"
		self.name = name[4:-2]
		
		# Define data in DB
		length = 8 + len(name) + 1
		IDAHacks.undefBytes(ea, length)
		idc.MakeStructEx(ea, length, "_TypeDescriptor")
		
		# Make a name, if not there
		name = "??_R0?AV" + self.name + "@@@8"
		if name != idc.Name(ea) :
			idc.MakeNameEx(ea, name, 0)
	# End of __init__()
	
	def __str__(self) :
		return "RTTI TypeDescriptor at %08x for `%s'" % (self.ea, self.name)
	# End of __str__()
	
# End of MsvcRttiTypeDescriptor

id = idc.GetStrucIdByName("_TypeDescriptor")
if id : idc.DelStruc(id)
id = idc.AddStrucEx(-1, "_TypeDescriptor", 0);
idc.AddStrucMember(id, "pVFTable",	0,	0x25500400,	0XFFFFFFFF,	4,	0XFFFFFFFF,	0,	0x000002);
idc.AddStrucMember(id, "spare",	0X4,	0x25500400,	0XFFFFFFFF,	4,	0XFFFFFFFF,	0,	0x000002);
idc.AddStrucMember(id, "name",	0X8,	0x50000400,	idc.ASCSTR_C,	0);
