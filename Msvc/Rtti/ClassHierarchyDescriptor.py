import idc
import IDAHacks
import RttiError
IDAHacks = reload(IDAHacks)
RttiError = reload(RttiError)

class ClassHierarchyDescriptor :
	"""
	"""
	
	def __init__(self, ea) :
		
		self.ea = ea
		
		# unsigned int signature;
		# unsigned int attributes;
		# unsigned int numBaseClasses;
		# RTTIBaseClassArray *pBaseClassArray;
		
		self.attributes = IDAHacks.getUInt32(ea + 4)
		self.hasMultipleBases = (self.attributes & 1) != 0
		self.hasVirtualBases = (self.attributes & 2) != 0
		
		baseCount = IDAHacks.getUInt32(ea + 8)
		if baseCount == 0 :
			raise RttiError.RttiError("ClassHierarchyDescriptor.numBaseClasses is zero.")
			
		self.baseTypeDescriptors = None
		self.baseTypePtrs = []
		self.baseArrayPtr = IDAHacks.getUInt32(ea + 12)
		IDAHacks.undefBytes(self.baseArrayPtr, baseCount * 4) # FIXME: 64-bitness
		
		basePtr = self.baseArrayPtr
		while baseCount > 0 :
			self.baseTypePtrs.append(IDAHacks.getUInt32(basePtr))
			idc.MakeDword(basePtr)
			basePtr += 4
			baseCount -= 1
		
		# Define data in DB
		IDAHacks.undefBytes(ea, 16)
		idc.MakeStructEx(ea, -1, "_s__RTTIClassHierarchyDescriptor")
	# End of __init__()
	
	def __str__(self) :
		text = "RTTI ClassHierarchyDescriptor at %08x\n" % (self.ea)
		inheritance = "MultipleInheritance" if self.hasMultipleBases else "SingleInheritance"
		vbase = "VirtualInheritance" if self.hasVirtualBases else ""
		text += "    Attributes: %s%s\n" % (inheritance, vbase)
		text += "    BaseDescrs: %s\n" % (" ".join(map(lambda x : "%08x" % x, self.baseTypePtrs)))
		return text
	# End of __str__()
	
	def resolve(self, rtti) :
		"""
		Resolve related objects via the RTTI db object.
		"""
		
		try :
			self.baseTypeDescriptors = [rtti.baseClassDescriptors[p] for p in self.baseTypePtrs]
		except KeyError as e :
			raise RttiError.RttiError("RTTI ClassHierarchyDescriptor at %08x: references an undefined BaseClassDescriptor2 at %08x." % (self.ea, e.args[0]))
			
		name = self.baseTypeDescriptors[0].typeDescriptor.nameMangled
		idc.MakeNameEx(self.baseArrayPtr, "??_R2" + name + "8", 0)
		idc.MakeNameEx(self.ea, "??_R3" + name + "8", 0)
		pass
	# End of resolve()
# End of ClassHierarchyDescriptor

id = idc.GetStrucIdByName("_s__RTTIClassHierarchyDescriptor");
if id : idc.DelStruc(id)
id = idc.AddStrucEx(-1, "_s__RTTIClassHierarchyDescriptor", 0);
idc.AddStrucMember(id,"signature",	0,	0x20000400,	-1,	4);
idc.AddStrucMember(id,"attributes",	0X4,	0x20000400,	-1,	4);
idc.AddStrucMember(id,"numBaseClasses",	0X8,	0x20000400,	-1,	4);
idc.AddStrucMember(id,"pBaseClassArray",	0XC,	0x25500400,	0XFFFFFFFF,	4,	0XFFFFFFFF,	0,	0x000002);
