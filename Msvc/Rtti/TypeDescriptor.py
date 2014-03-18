import idc
import IDAHacks
import RttiError
IDAHacks = reload(IDAHacks)
RttiError = reload(RttiError)

class TypeDescriptor :
	"""
	"""
	
	def __init__(self, ea) :
		"""
		Construct the TypeDescriptor object from the information at the given EA.
		"""
		
		self.ea = ea
		
		# const void *pVFTable;
		# void *spare;
		# char name[];
		
		self.vtblAddress = IDAHacks.getUInt32(ea)
		name = IDAHacks.getAsciiz(ea + 8) # FIXME: 64-bit
		if name[:4] != ".?AV":
			raise RttiError.RttiError("TypeDescriptor.name does not start with '.?AV'.")
		if name[-2:] != "@@":
			raise RttiError.RttiError("TypeDescriptor.name does not end with '@@'.")
		# Cut extra chars: ".?AV"
		self.nameMangled = name[4:]
		# Use vftable mangling to convert this to a demangled form
		self.name = idc.Demangle("??_7" + self.nameMangled + "6B@", 0x00004006)[:-11].strip()

		# Define data in DB
		length = 8 + len(name) + 1
		IDAHacks.undefBytes(ea, length)
		idc.MakeStructEx(ea, length, "_TypeDescriptor")
		
		name = "??_R0?AV" + self.nameMangled + "@8"
		idc.MakeNameEx(ea, name, 0)
			
		# TODO: handle align directives.
	# End of __init__()
	
	def __str__(self) :
		return "RTTI TypeDescriptor at %08x for `%s'" % (self.ea, self.name)
	# End of __str__()
	
# End of TypeDescriptor

id = idc.GetStrucIdByName("_TypeDescriptor")
if id : idc.DelStruc(id)
id = idc.AddStrucEx(-1, "_TypeDescriptor", 0);
idc.AddStrucMember(id, "pVFTable",	0,	0x25500400,	0XFFFFFFFF,	4,	0XFFFFFFFF,	0,	0x000002);
idc.AddStrucMember(id, "spare",	0X4,	0x25500400,	0XFFFFFFFF,	4,	0XFFFFFFFF,	0,	0x000002);
idc.AddStrucMember(id, "name",	0X8,	0x50000400,	idc.ASCSTR_C,	0);
