import idc
import IDAHacks
import RttiError
IDAHacks = reload(IDAHacks)
RttiError = reload(RttiError)

class BaseClassDescriptor2 :
	"""
		
		struct PMD
		{
		  int mdisp;
		  int pdisp;
		  int vdisp;
		};
	"""
	
	def __init__(self, rtti, ea) :
		
		self.ea = ea
		
		# TypeDescriptor *pTypeDescriptor;
		# unsigned int numContainedBases;
		# _PMD where;
		# unsigned int attributes;
		# RTTIClassHierarchyDescriptor *pClassDescriptor;
		
		self.typeDescriptor = rtti.getTypeDescriptor(idc.Dword(ea))
		baseCount = idc.Dword(ea + 4)
		self.mdisp = idc.Dword(ea + 8)
		self.pdisp = idc.Dword(ea + 12)
		self.vdisp = idc.Dword(ea + 16)
		self.attributes = idc.Dword(ea + 20)
		
		# Define data in DB
		IDAHacks.undefBytes(ea, 28)
		idc.MakeStructEx(ea, -1, "_s__RTTIBaseClassDescriptor2")
		
		# Make a name, if not there ??_R1 A@ ?0A@ EA@ {class}@@8
		#name = "??_R0?AV" + self.name + "@@@8"
		#if name != idc.Name(ea) :
		#	idc.MakeNameEx(ea, name, 0)
	# End of __init__()
	
	def __str__(self) :
		return "RTTI BaseClassDescriptor2 at %08x" % (self.ea)
	# End of __str__()
	
	def resolve(self, rtti) :
		self.classDescriptor = rtti.getClassHierarchyDescriptor(idc.Dword(self.ea + 24))
	# End of resolve()
#

id = idc.GetStrucIdByName("_s__RTTIBaseClassDescriptor2");
if id : idc.DelStruc(id)
id = idc.AddStrucEx(-1, "_s__RTTIBaseClassDescriptor2", 0);
idc.AddStrucMember(id,"pTypeDescriptor",	0,	0x25500400,	0XFFFFFFFF,	4,	0XFFFFFFFF,	0,	0x000002);
idc.AddStrucMember(id,"numContainedBases",	0X4,	0x20000400,	-1,	4);
idc.AddStrucMember(id,"mdisp",	0X8,	0x20000400,	-1,	4);
idc.AddStrucMember(id,"pdisp",	0XC,	0x20000400,	-1,	4);
idc.AddStrucMember(id,"vdisp",	0X10,	0x20000400,	-1,	4);
idc.AddStrucMember(id,"attributes",	0X14,	0x20000400,	-1,	4);
idc.AddStrucMember(id,"pClassDescriptor",	0X18,	0x25500400,	0XFFFFFFFF,	4,	0XFFFFFFFF,	0,	0x000002);
