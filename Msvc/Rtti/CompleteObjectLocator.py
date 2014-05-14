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
	
	def __init__(self, ea) :
		"""
		Construct the RTTICompleteObjectLocator object from the information at the given EA.
		"""
		
		self.ea = ea
		
		# unsigned int signature; // don't care
		# unsigned int offset; // offset of this vtable in the complete class
		# unsigned int cdOffset; // constructor displacement offset
		# TypeDescriptor *pTypeDescriptor; // TypeDescriptor of the complete class
		# RTTIClassHierarchyDescriptor *pClassDescriptor; // describes inheritance hierarchy
		
		self.vftableOffset = IDAHacks.getUInt32(ea + 4)
		self.cdOffset = IDAHacks.getUInt32(ea + 8)
		self.typeDescriptorPtr = IDAHacks.getUInt32(ea + 12)
		self.classDescriptorPtr = IDAHacks.getUInt32(ea + 16)
		self.typeDescriptor = None
		self.classDescriptor = None
		self.relatedBaseType = None
		
		# Define data in DB
		IDAHacks.undefBytes(ea, 20)
		idc.MakeStructEx(ea, -1, "_s__RTTICompleteObjectLocator")
	# End of __init__()
	
	def __str__(self) :
		return "RTTI CompleteObjectLocator at %08x for `%s'" % (self.ea, self.typeDescriptor.name)
	# End of __str__()
	
	def __getattr__(self, name) :
		if name == "typeNameMangled" :
			if self.typeDescriptor is not None :
				return self.typeDescriptor.nameMangled
			else :
				return None
		if name == "baseTypeNameMangled" :
			if self.classDescriptor is not None :
				return self.relatedBaseType.typeDescriptor.nameMangled
			else :
				return None
		raise AttributeError
	# End of __getattr__()
	
	def resolve(self, rtti) :
		"""
		Resolve related objects via the RTTI db object.
		"""
		
		try :
			self.typeDescriptor = rtti.typeDescriptors[self.typeDescriptorPtr]
		except KeyError as e:
			raise RttiError.RttiError("RTTI CompleteObjectLocator at %08x: references an undefined TypeDescriptor at %08x." % (self.ea, e.args[0]))
		try :
			self.classDescriptor = rtti.classHierarchyDescriptors[self.classDescriptorPtr]
		except KeyError as e:
			raise RttiError.RttiError("RTTI CompleteObjectLocator at %08x: references an undefined ClassHierarchyDescriptor at %08x." % (self.ea, e.args[0]))
		
		# Make a name, if not there
		# The name of complete object locator depends on a lot of factors.
		# Won't be that easy to figure this out right away.
		# ??_R4 CC@@ 6B AA@@ @
		if self.classDescriptor.usesMultipleInheritance :
			# TODO: determine whether this search is robust enough.
			for bcd in self.classDescriptor.baseTypeDescriptors :
				if bcd.typeDescriptor != self.typeDescriptor and bcd.mdisp == self.vftableOffset :
					self.relatedBaseType = bcd
					break
			else :
				print "WARN: no matched offset for %s" % self
				return
			
			name = "??_R4" + self.typeDescriptor.nameMangled + "6B"
			name += self.relatedBaseType.typeDescriptor.nameMangled + "@"
			idc.MakeNameEx(self.ea, name, 0)
		else :
			name = "??_R4" + self.typeDescriptor.nameMangled + "6B@"
			idc.MakeNameEx(self.ea, name, 0)
	# End of resolve()
#

id = idc.GetStrucIdByName("_s__RTTICompleteObjectLocator");
if id == 4294967295 :
        print "Defining _s__RTTICompleteObjectLocator struct."
        id = idc.AddStrucEx(-1, "_s__RTTICompleteObjectLocator", 0);
        idc.AddStrucMember(id,"signature",	0,	0x20000400,	-1,	4);
        idc.AddStrucMember(id,"offset",	0X4,	0x20000400,	-1,	4);
        idc.AddStrucMember(id,"cdOffset",	0X8,	0x20000400,	-1,	4);
        idc.AddStrucMember(id,"pTypeDescriptor",	0XC,	0x25500400,	0XFFFFFFFF,	4,	0XFFFFFFFF,	0,	0x000002);
        idc.AddStrucMember(id,"pClassDescriptor",	0X10,	0x25500400,	0XFFFFFFFF,	4,	0XFFFFFFFF,	0,	0x000002);
