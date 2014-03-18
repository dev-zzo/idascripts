import TypeDescriptor
import CompleteObjectLocator
import ClassHierarchyDescriptor
import BaseClassDescriptor2
import RttiInfo
TypeDescriptor = reload(TypeDescriptor)
CompleteObjectLocator = reload(CompleteObjectLocator)
ClassHierarchyDescriptor = reload(ClassHierarchyDescriptor)
BaseClassDescriptor2 = reload(BaseClassDescriptor2)
RttiInfo = reload(RttiInfo)
import IDAHacks
IDAHacks = reload(IDAHacks)

def findTypeDescriptorCandidates() :
	"""
	Locate any candidates for a type descriptor object.
	Detected by the pattern: {pointer} {0} ".?AV"
	"""
	
	results = []
	
	# The objects are defined within the .data section usually.
	dataBounds = IDAHacks.getSegBoundaries(".data")
	# vfptr offsets are into the .rdata section.
	rdataBounds = IDAHacks.getSegBoundaries(".rdata")
	
	ea = dataBounds[0] + 8
	while ea < dataBounds[1] :
		if IDAHacks.getUInt32(ea) == 0x56413F2E and IDAHacks.getUInt32(ea - 4) == 0:
			# Note: this check can potentially be skipped...
			vfptr = IDAHacks.getUInt32(ea - 8)
			if rdataBounds[0] <= vfptr < rdataBounds[1] :
				# print "Found candidate @%08x" % (ea - 8)
				results.append(ea - 8)
		ea += 4
	
	return results
# End of findTypeDescriptorCandidates()

def findVftableCandidates() :
	"""
	Locate potential vftables (only those that have RTTI information).
	Detected by the pattern: {ptr into rdata} {ptr into text}
	"""
	
	results = []
	
	dataBounds = IDAHacks.getSegBoundaries(".data")
	rdataBounds = IDAHacks.getSegBoundaries(".rdata")
	textBounds = IDAHacks.getSegBoundaries(".text")
	
	ea = rdataBounds[0]
	while ea < (rdataBounds[1] - 4) :
		colPtr = IDAHacks.getUInt32(ea)
		vfuncPtr = IDAHacks.getUInt32(ea + 4)
		if (rdataBounds[0] <= colPtr < rdataBounds[1]) and (textBounds[0] <= vfuncPtr < textBounds[1]) :
			# Check that this is really a complete object locator.
			tdPtr = IDAHacks.getUInt32(colPtr + 12)
			if IDAHacks.getUInt32(tdPtr + 8) == 0x56413F2E :
				ea += 4
				results.append(ea)
		ea += 4
	
	return results
# End of findVftableCandidates()

def scan(rtti) :
	print "RttiScanner: scanning for RTTI type descriptors."
	tds = findTypeDescriptorCandidates()
	for ea in tds :
		x = TypeDescriptor.TypeDescriptor(ea)
		rtti.typeDescriptors[ea] = x
		print x
		
		c = RttiInfo.TypeInfo(x)
		rtti.types[x.nameMangled] = c
	
	print "RttiScanner: scanning for vftables."
	vftables = findVftableCandidates()
	
	print "RttiScanner: processing vftables."
	for vft in vftables :
		colPtr = IDAHacks.getUInt32(vft - 4)
		col = CompleteObjectLocator.CompleteObjectLocator(colPtr)
		rtti.completeObjectLocators[colPtr] = col
		
		# Has to exist.
		td = rtti.typeDescriptors[col.typeDescriptorPtr]
		# print "%08x: a vftable for `%s'" % (vft, td.name)
		cls = rtti.types[td.nameMangled]
		cls.vftables.append(vft)
		cls.completeObjectLocators.append(col)
		
		# Work around the Class Hierarchy Descriptor object
		chdPtr = col.classDescriptorPtr
		try :
			chd = rtti.classHierarchyDescriptors[chdPtr]
		except :
			chd = ClassHierarchyDescriptor.ClassHierarchyDescriptor(chdPtr)
			print chd
			rtti.classHierarchyDescriptors[chdPtr] = chd
			cls.classHierarchyDescriptor = chd
			for bcdPtr in chd.baseTypePtrs :
				try :
					bcd = rtti.baseClassDescriptors[bcdPtr]
				except :
					bcd = BaseClassDescriptor2.BaseClassDescriptor2(bcdPtr)
					print bcd
					rtti.baseClassDescriptors[bcdPtr] = bcd
					#bcd.resolve(rtti)
			#chd.resolve(rtti)
		#col.resolve(rtti)
	
	print "RttiScanner: resolving references."
	rtti.resolve()
	
	print "RttiScanner: done here."
# End of scan()
