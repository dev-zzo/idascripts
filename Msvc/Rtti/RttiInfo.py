import TypeDescriptor
import CompleteObjectLocator
import ClassHierarchyDescriptor
import BaseClassDescriptor2
TypeDescriptor = reload(TypeDescriptor)
CompleteObjectLocator = reload(CompleteObjectLocator)
ClassHierarchyDescriptor = reload(ClassHierarchyDescriptor)
BaseClassDescriptor2 = reload(BaseClassDescriptor2)

class RttiInfo :
	"""
	Serves as a collection of all RTTI-related information.
	"""
	def __init__(self) :
		self.typeDescriptors = dict()
		self.completeObjectLocators = dict()
		self.classHierarchyDescriptors = dict()
		self.baseClassDescriptors = dict()
		pass
		
	def getTypeDescriptor(self, ea) :
		try :
			return self.typeDescriptors[ea]
		except:
			x = TypeDescriptor.TypeDescriptor(self, ea)
			self.typeDescriptors[ea] = x
			return x
	# End of getTypeDescriptor()
	
	def getCompleteObjectLocator(self, ea) :
		try :
			return self.completeObjectLocators[ea]
		except:
			x = CompleteObjectLocator.CompleteObjectLocator(self, ea)
			self.completeObjectLocators[ea] = x
			return x
	# End of getCompleteObjectLocator()
	
	def getClassHierarchyDescriptor(self, ea) :
		try :
			return self.classHierarchyDescriptors[ea]
		except:
			x = ClassHierarchyDescriptor.ClassHierarchyDescriptor(self, ea)
			self.classHierarchyDescriptors[ea] = x
			return x
	# End of getCompleteObjectLocator()
	
	def getBaseClassDescriptor2(self, ea) :
		try :
			return self.baseClassDescriptors[ea]
		except:
			x = BaseClassDescriptor2.BaseClassDescriptor2(self, ea)
			self.baseClassDescriptors[ea] = x
			x.resolve(self)
			return x
	# End of getCompleteObjectLocator()
	
# End of Rtti

