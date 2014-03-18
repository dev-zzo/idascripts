import string
import idc
import IDAHacks
import RttiError
IDAHacks = reload(IDAHacks)
RttiError = reload(RttiError)

def mangleNumber(num) :
	if num == 0 :
		return "@"
	sign = ""
	if num < 0 :
		sign = "?"
		num = -num
	numtext = hex(num).upper()[2:-1]
	numtext = sign + numtext.translate(string.maketrans('0123456789ABCDEF', 'ABCDEFGHIJKLMNOP')) + "@"
	return numtext

class BaseClassDescriptor2 :
	"""
	"""
	
	def __init__(self, ea) :
		
		self.ea = ea
		
		# TypeDescriptor *pTypeDescriptor;
		# unsigned int numContainedBases;
		# _PMD where;
		# unsigned int attributes;
		# RTTIClassHierarchyDescriptor *pClassDescriptor;
		
		self.typeDescriptorPtr = IDAHacks.getUInt32(ea)
		baseCount = IDAHacks.getUInt32(ea + 4)
		self.mdisp = IDAHacks.getInt32(ea + 8)
		self.pdisp = IDAHacks.getInt32(ea + 12)
		self.vdisp = IDAHacks.getInt32(ea + 16)
		self.attributes = IDAHacks.getUInt32(ea + 20)
		self.classDescriptorPtr = IDAHacks.getUInt32(ea + 24)
		
		# Define data in DB
		IDAHacks.undefBytes(ea, 28)
		idc.MakeStructEx(ea, -1, "_s__RTTIBaseClassDescriptor2")
	# End of __init__()
	
	def __str__(self) :
		return "RTTI BaseClassDescriptor2 at %08x" % (self.ea)
	# End of __str__()
	
	def resolve(self, rtti) :
		"""
		Resolve related objects via the RTTI db object.
		"""

		try :
			self.typeDescriptor = rtti.typeDescriptors[self.typeDescriptorPtr]
		except KeyError as e:
			raise RttiError.RttiError("RTTI BaseClassDescriptor2 at %08x: references an undefined TypeDescriptor at %08x." % (self.ea, e.args[0]))
		try :
			self.classDescriptor = rtti.classHierarchyDescriptors[self.classDescriptorPtr]
		except KeyError as e:
			raise RttiError.RttiError("RTTI BaseClassDescriptor2 at %08x: references an undefined ClassHierarchyDescriptor at %08x." % (self.ea, e.args[0]))
		
		# Make a name, if not there
		name = "??_R1"
		name += mangleNumber(self.mdisp)
		name += mangleNumber(self.pdisp)
		name += mangleNumber(self.vdisp)
		name += mangleNumber(self.attributes)
		name += self.typeDescriptor.nameMangled + "8"
		idc.MakeNameEx(self.ea, name, 0)
	# End of resolve()
# End of BaseClassDescriptor2

id = idc.GetStrucIdByName("_s__RTTIBaseClassDescriptor2");
if id : idc.DelStruc(id)
id = idc.AddStrucEx(-1, "_s__RTTIBaseClassDescriptor2", 0);
idc.AddStrucMember(id,"pTypeDescriptor",	0,	0x25500400,	0XFFFFFFFF,	4,	0XFFFFFFFF,	0,	0x000002);
idc.AddStrucMember(id,"numContainedBases",	0X4,	0x20000400,	-1,	4);
idc.AddStrucMember(id,"mdisp",	0X8,	0x20200400,	-1,	4);
idc.AddStrucMember(id,"pdisp",	0XC,	0x20200400,	-1,	4);
idc.AddStrucMember(id,"vdisp",	0X10,	0x20200400,	-1,	4);
idc.AddStrucMember(id,"attributes",	0X14,	0x20000400,	-1,	4);
idc.AddStrucMember(id,"pClassDescriptor",	0X18,	0x25500400,	0XFFFFFFFF,	4,	0XFFFFFFFF,	0,	0x000002);
