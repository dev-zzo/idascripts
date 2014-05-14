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

def findTypeDescriptorCandidates(searchBounds, vfptrBounds) :
	"""
	Locate any candidates for a type descriptor object.
	Detected by the pattern: {pointer} {0} ".?AV"
	"""
	
	results = []
	
	ea = searchBounds[0]
	while ea < searchBounds[1] - 8 :
		# if (ea % 0x2000) == 0 : print "At %08x" % ea
		if IDAHacks.getUInt32(ea + 4) == 0 :
			v = IDAHacks.getUInt32(ea + 8)
			if TypeDescriptor.TypeDescriptor.isMaybeTypeName(v) :
				# Note: this check can potentially be skipped...
				vfptr = IDAHacks.getUInt32(ea)
				if vfptrBounds[0] <= vfptr < vfptrBounds[1] :
					# print "Found candidate @%08x" % (ea)
					results.append(ea)
		ea += 4
	return results
# End of findTypeDescriptorCandidates()

def processTypeDescriptors(rtti) :
	# The objects are defined within the .data section usually.
	# vfptr offsets are into the .rdata section.
	dataBounds = IDAHacks.getSegBoundaries(".data")
	rdataBounds = IDAHacks.getSegBoundaries(".rdata")
	tds = findTypeDescriptorCandidates(dataBounds, rdataBounds)
	for ea in tds :
		x = TypeDescriptor.TypeDescriptor(ea)
		rtti.typeDescriptors[ea] = x
                print x
		c = RttiInfo.TypeInfo(x)
		rtti.types[x.nameMangled] = c

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
			# The check can use the existing TypeDescriptor DB from RTTI...
			v = IDAHacks.getUInt32(tdPtr + 8)
			if TypeDescriptor.TypeDescriptor.isMaybeTypeName(v) :
				ea += 4
				results.append(ea)
		ea += 4
	
	return results
# End of findVftableCandidates()

def resolveBCD(bcdPtr, rtti) :
	try :
		bcd = rtti.baseClassDescriptors[bcdPtr]
	except :
		bcd = BaseClassDescriptor2.BaseClassDescriptor2(bcdPtr)
		print bcd
		rtti.baseClassDescriptors[bcdPtr] = bcd
		resolveCHD(bcd.classDescriptorPtr, rtti)
	return bcd
# End of resolveBCD()

def resolveCHD(chdPtr, rtti) :
	try :
		chd = rtti.classHierarchyDescriptors[chdPtr]
	except :
		chd = ClassHierarchyDescriptor.ClassHierarchyDescriptor(chdPtr)
		print chd
		rtti.classHierarchyDescriptors[chdPtr] = chd
		for bcdPtr in chd.baseTypePtrs :
			bcd = resolveBCD(bcdPtr, rtti)
	return chd
# End of resolveCHD()

def scan(rtti) :
	print "RttiScanner: scanning for RTTI type descriptors (takes a while)."
	processTypeDescriptors(rtti)
	
	print "RttiScanner: scanning for vftables (takes a while)."
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
		cls.classHierarchyDescriptor = resolveCHD(chdPtr, rtti)
	
	print "RttiScanner: resolving references."
	rtti.resolve()
	
	print "RttiScanner: done here."
# End of scan()
