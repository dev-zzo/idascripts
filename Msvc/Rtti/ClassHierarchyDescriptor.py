import idc
import IDAHacks
import RttiError
IDAHacks = reload(IDAHacks)
RttiError = reload(RttiError)

class ClassHierarchyDescriptor :
	"""
	"""
	
	def __init__(self, rtti, ea) :
		
		self.ea = ea
		
		# unsigned int signature;
		# unsigned int attributes;
		# unsigned int numBaseClasses;
		# RTTIBaseClassArray *pBaseClassArray;
		
		self.attributes = idc.Dword(ea + 4)
		self.baseClasses = []
		baseCount = idc.Dword(ea + 8)
		baseArray = None
		if baseCount > 0 :
			baseArray = idc.Dword(ea + 12)
			basePtr = baseArray
			while baseCount > 0 :
				# Define base class descriptor
				self.baseClasses.append(rtti.getBaseClassDescriptor2(idc.Dword(basePtr)))
				basePtr += 4
				baseCount -= 1
			# Name the base class array
			# ??_R2{class}@@8
			IDAHacks.undefBytes(baseArray, baseCount * 4) # FIXME: 64-bitness
			idc.MakeArray(baseArray, baseCount)
			name = "??_R2" + self.__getClassName() + "@@8"
			if name != idc.Name(baseArray) :
				idc.MakeNameEx(baseArray, name, 0)
		else :
			print str(self) + ": no base class descriptors defined."
		
		# Define data in DB
		IDAHacks.undefBytes(ea, 16)
		idc.MakeStructEx(ea, -1, "_s__RTTIClassHierarchyDescriptor")
		
		# Make a name, if not there
		name = "??_R3" + self.__getClassName() + "@@8"
		if name != idc.Name(ea) :
			idc.MakeNameEx(ea, name, 0)
	# End of __init__()
	
	def __str__(self) :
		return "RTTI ClassHierarchyDescriptor at %08x" % (self.ea)
	# End of __str__()
	
	def __getClassName(self) :
		"""
		Obtain the class name this CHD relates to.
		1) Use the xref from COL and get to TD.
		2) Use base class array[0].
		"""
		if self.baseClasses is not None and len(self.baseClasses) > 0 :
			baseDesc = self.baseClasses[0]
			return baseDesc.typeDescriptor.name
		return None
#

id = idc.GetStrucIdByName("_s__RTTIClassHierarchyDescriptor");
if id : idc.DelStruc(id)
id = idc.AddStrucEx(-1, "_s__RTTIClassHierarchyDescriptor", 0);
idc.AddStrucMember(id,"signature",	0,	0x20000400,	-1,	4);
idc.AddStrucMember(id,"attributes",	0X4,	0x20000400,	-1,	4);
idc.AddStrucMember(id,"numBaseClasses",	0X8,	0x20000400,	-1,	4);
idc.AddStrucMember(id,"pBaseClassArray",	0XC,	0x25500400,	0XFFFFFFFF,	4,	0XFFFFFFFF,	0,	0x000002);
