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
		
		# The address here is totally bogus. I wonder what this was used for.
		self.vtblAddress = IDAHacks.getUInt32(ea)
		
		name = IDAHacks.getAsciiz(ea + 8) # FIXME: 64-bit
		nameFullLength = len(name)
		# Sanity checks.
		if name[-2:] != "@@":
			raise RttiError.RttiError("TypeDescriptor.name does not end with '@@'.")
		# Remove the dot -- no use anyway.
		name = name[1:]
		if name[:3] == "?AV" :
			self.kind = "class"
			nameOffset = 3
		elif name[:3] == "?AU" :
			self.kind = "struct"
			nameOffset = 3
		elif name[:3] == "PAV" :
			# .PAVRSAFunction@CryptoPP@@
			self.kind = "pointer"
			nameOffset = 3
		elif name[:3] == "?AW" :
			# .?AW4BlockPaddingScheme@BlockPaddingSchemeDef@CryptoPP@@
			# TODO: what does that "4" mean?
			self.kind = "enum"
			nameOffset = 4
		else :
			raise RttiError.RttiError("TypeDescriptor.name is not recognised.")

		# Cut extra chars that don't fit into the mangled name
		self.nameMangled = name[nameOffset:]
		# Use vftable mangling to convert this to a demangled form
		# NOTE: may be incorrect.
		self.name = idc.Demangle("??_7" + self.nameMangled + "6B@", 0x00004006)[:-11].strip()

		# Define data in DB
		length = 8 + nameFullLength + 1
		IDAHacks.undefBytes(ea, length)
		idc.MakeStructEx(ea, length, "_TypeDescriptor")
		
		# Use the full name with the starting "?A" here.
		# IDA is able to demangle it properly.
		name = "??_R0" + name + "@8"
		idc.MakeNameEx(ea, name, 0)
			
		# TODO: handle align directives.
	# End of __init__()
	
	def __str__(self) :
		return "RTTI TypeDescriptor at %08x for `%s'" % (self.ea, self.name)
	# End of __str__()
	
	@staticmethod
	def isMaybeTypeName(v) :
		"""
		Check that the value v can be a beginning of a type name.
		"""
		# ".?AV", ".PAV", ".?AU", ".PAU", ".?AW"
		return v == 0x56413F2E or v == 0x5641502E or v == 0x55413F2E or v == 0x5541502E or v == 0x57413F2E
	# End of isValidSignature()
	
# End of TypeDescriptor

id = idc.GetStrucIdByName("_TypeDescriptor")
if id : idc.DelStruc(id)
id = idc.AddStrucEx(-1, "_TypeDescriptor", 0);
idc.AddStrucMember(id, "pVFTable",	0,	0x25500400,	0XFFFFFFFF,	4,	0XFFFFFFFF,	0,	0x000002);
idc.AddStrucMember(id, "spare",	0X4,	0x25500400,	0XFFFFFFFF,	4,	0XFFFFFFFF,	0,	0x000002);
idc.AddStrucMember(id, "name",	0X8,	0x50000400,	idc.ASCSTR_C,	0);
