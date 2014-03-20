import idc
import TypeDescriptor
import CompleteObjectLocator
import ClassHierarchyDescriptor
import BaseClassDescriptor2
import IDAHacks
TypeDescriptor = reload(TypeDescriptor)
CompleteObjectLocator = reload(CompleteObjectLocator)
ClassHierarchyDescriptor = reload(ClassHierarchyDescriptor)
BaseClassDescriptor2 = reload(BaseClassDescriptor2)
IDAHacks = reload(IDAHacks)

class TypeInfo :
	"""
	Encapsulates all the info related to a single class
	"""
	def __init__(self, td) :
		self.nameMangled = td.nameMangled
		self.typeDescriptor = td
		self.vftables = []
		self.completeObjectLocators = []
		self.classHierarchyDescriptor = None
	# End of __init__()
		
# End of ClassInfo

class RttiInfo :
	"""
	Serves as a collection of all RTTI-related information.
	"""
	
	def __init__(self) :
		# Map type name (mangled) -> class
		self.types = dict()
		
		# Map EA -> object
		self.typeDescriptors = dict()
		self.completeObjectLocators = dict()
		self.classHierarchyDescriptors = dict()
		self.baseClassDescriptors = dict()
	# End of __init__()
	
	def resolve(self) :
		"""
		Resolve all inter-object links
		"""
		
		for p, x in self.baseClassDescriptors.iteritems() : x.resolve(self)
		for p, x in self.classHierarchyDescriptors.iteritems() : x.resolve(self)
		for p, x in self.completeObjectLocators.iteritems() : x.resolve(self)
		
		# TODO: Move this part to vftables module. Not really RTTI.
		for p, x in self.types.iteritems() :
			for vfptr in x.vftables :
				colName = idc.Name(IDAHacks.getUInt32(vfptr - 4))
				idc.MakeName(vfptr, "??_7" + colName[5:])
	# End of resolve()
	
# End of Rtti

