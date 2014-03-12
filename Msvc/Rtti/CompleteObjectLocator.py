import idc
import IDAHacks
import RttiError
IDAHacks = reload(IDAHacks)
RttiError = reload(RttiError)

class CompleteObjectLocator :
	"""
	The CompleteObjectLocator structure allows compiler to find 
	the location of the complete object from a specific vftable pointer 
	(since a class can have several of them).
	"""
	
	def __init__(self, rtti, ea) :
		"""
		Construct the RTTICompleteObjectLocator object from the information at the given EA.
		"""
		
		self.ea = ea
		
		# unsigned int signature; // don't care
		# unsigned int offset; // offset of this vtable in the complete class
		# unsigned int cdOffset; // constructor displacement offset
		# TypeDescriptor *pTypeDescriptor; // TypeDescriptor of the complete class
		# RTTIClassHierarchyDescriptor *pClassDescriptor; // describes inheritance hierarchy
		
		self.vftableOffset = idc.Dword(ea + 4)
		self.cdOffset = idc.Dword(ea + 8)
		self.typeDescriptor = rtti.getTypeDescriptor(idc.Dword(ea + 12))
		self.classDescriptor = rtti.getClassHierarchyDescriptor(idc.Dword(ea + 16))
		
		# Define data in DB
		IDAHacks.undefBytes(ea, 20)
		idc.MakeStructEx(ea, -1, "_s__RTTICompleteObjectLocator")
		
		# Make a name, if not there
		name = "??_R4" + self.typeDescriptor.name + "@@6B@"
		if name != idc.Name(ea) :
			idc.MakeNameEx(ea, name, 0)
	# End of __init__()
	
	def __str__(self) :
		return "RTTI CompleteObjectLocator at %08x for `%s'" % (self.ea, self.typeDescriptor.name)
	# End of __str__()
#

id = idc.GetStrucIdByName("_s__RTTICompleteObjectLocator");
if id : idc.DelStruc(id)
id = idc.AddStrucEx(-1, "_s__RTTICompleteObjectLocator", 0);
idc.AddStrucMember(id,"signature",	0,	0x20000400,	-1,	4);
idc.AddStrucMember(id,"offset",	0X4,	0x20000400,	-1,	4);
idc.AddStrucMember(id,"cdOffset",	0X8,	0x20000400,	-1,	4);
idc.AddStrucMember(id,"pTypeDescriptor",	0XC,	0x25500400,	0XFFFFFFFF,	4,	0XFFFFFFFF,	0,	0x000002);
idc.AddStrucMember(id,"pClassDescriptor",	0X10,	0x25500400,	0XFFFFFFFF,	4,	0XFFFFFFFF,	0,	0x000002);
