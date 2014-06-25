import idc
import idaapi
import idautils
import string
import traceback
from IDAHacks import *

#
# References:
#
# http://www.openrce.org/articles/full_view/23
# 
#

class RttiError(Exception) :
    def __init__(self, msg) :
        self.msg = msg
    def __str__(self) :
        return self.msg

class PMD :
    def __init__(self, mdisp, pdisp, vdisp) :
        # member displacement
        self.mdisp = mdisp
        # vbtable displacement
        self.pdisp = pdisp
        # displacement inside vbtable
        self.vdisp = vdisp

#
# Define all the RTTI data types.
# TODO: Deal with different compiler versions.
#

id = idc.GetStrucIdByName("_TypeDescriptor")
if id == 4294967295 :
    # print "Defining _TypeDescriptor struct."
    id = idc.AddStrucEx(-1, "_TypeDescriptor", 0);
    idc.AddStrucMember(id, "pVFTable",  0,  0x25500400, 0XFFFFFFFF, 4,  0XFFFFFFFF, 0,  0x000002);
    idc.AddStrucMember(id, "spare", 0X4,    0x25500400, 0XFFFFFFFF, 4,  0XFFFFFFFF, 0,  0x000002);
    idc.AddStrucMember(id, "name",  0X8,    0x50000400, idc.ASCSTR_C,   0);

id = idc.GetStrucIdByName("_s__RTTICompleteObjectLocator");
if id == 4294967295 :
    # print "Defining _s__RTTICompleteObjectLocator struct."
    id = idc.AddStrucEx(-1, "_s__RTTICompleteObjectLocator", 0);
    idc.AddStrucMember(id,"signature",  0,  0x20000400, -1, 4);
    idc.AddStrucMember(id,"offset", 0X4,    0x20000400, -1, 4);
    idc.AddStrucMember(id,"cdOffset",   0X8,    0x20000400, -1, 4);
    idc.AddStrucMember(id,"pTypeDescriptor",    0XC,    0x25500400, 0XFFFFFFFF, 4,  0XFFFFFFFF, 0,  0x000002);
    idc.AddStrucMember(id,"pClassDescriptor",   0X10,   0x25500400, 0XFFFFFFFF, 4,  0XFFFFFFFF, 0,  0x000002);

id = idc.GetStrucIdByName("_s__RTTIClassHierarchyDescriptor");
if id == 4294967295 :
    # print "Defining _s__RTTIClassHierarchyDescriptor struct."
    id = idc.AddStrucEx(-1, "_s__RTTIClassHierarchyDescriptor", 0);
    idc.AddStrucMember(id,"signature",  0,  0x20000400, -1, 4);
    idc.AddStrucMember(id,"attributes", 0X4,    0x20000400, -1, 4);
    idc.AddStrucMember(id,"numBaseClasses", 0X8,    0x20000400, -1, 4);
    idc.AddStrucMember(id,"pBaseClassArray",    0XC,    0x25500400, 0XFFFFFFFF, 4,  0XFFFFFFFF, 0,  0x000002);

# Used by e.g. VC8
id = idc.GetStrucIdByName("_s__RTTIBaseClassDescriptor");
if id == 4294967295 :
    # print "Defining _s__RTTIBaseClassDescriptor struct."
    id = idc.AddStrucEx(-1, "_s__RTTIBaseClassDescriptor", 0);
    idc.AddStrucMember(id,"pTypeDescriptor",    0,  0x25500400, 0XFFFFFFFF, 4,  0XFFFFFFFF, 0,  0x000002);
    idc.AddStrucMember(id,"numContainedBases",  0X4,    0x20000400, -1, 4);
    idc.AddStrucMember(id,"mdisp",  0X8,    0x20200400, -1, 4);
    idc.AddStrucMember(id,"pdisp",  0XC,    0x20200400, -1, 4);
    idc.AddStrucMember(id,"vdisp",  0X10,   0x20200400, -1, 4);
    idc.AddStrucMember(id,"attributes", 0X14,   0x20000400, -1, 4);

# Used by e.g. VC10
id = idc.GetStrucIdByName("_s__RTTIBaseClassDescriptor2");
if id == 4294967295 :
    # print "Defining _s__RTTIBaseClassDescriptor2 struct."
    id = idc.AddStrucEx(-1, "_s__RTTIBaseClassDescriptor2", 0);
    idc.AddStrucMember(id,"pTypeDescriptor",    0,  0x25500400, 0XFFFFFFFF, 4,  0XFFFFFFFF, 0,  0x000002);
    idc.AddStrucMember(id,"numContainedBases",  0X4,    0x20000400, -1, 4);
    idc.AddStrucMember(id,"mdisp",  0X8,    0x20200400, -1, 4);
    idc.AddStrucMember(id,"pdisp",  0XC,    0x20200400, -1, 4);
    idc.AddStrucMember(id,"vdisp",  0X10,   0x20200400, -1, 4);
    idc.AddStrucMember(id,"attributes", 0X14,   0x20000400, -1, 4);
    idc.AddStrucMember(id,"pClassDescriptor",   0X18,   0x25500400, 0XFFFFFFFF, 4,  0XFFFFFFFF, 0,  0x000002);

#
# TypeDescriptor handling.
#

class TypeDescriptor :
    """
    TODO: describe me.
    """

    def __init__(self, ea) :
        self.ea = ea
        TypeDescriptor.define(ea)

    def __eq__(self, other) :
        if type(other) is not type(self) :
            return False
        return self.ea == other.ea

    def __ne__(self, other) :
        return not self.__eq__(other)

    def __str__(self) :
        return "%08X: RTTI Type Descriptor for `%s'" % (self.ea, self.typeName)

    @property
    def mangledName(self) :
        return getAsciiz(self.ea + 9)

    @property
    def baseMangledName(self) :
        name = self.mangledName
        if name[:2] != '?A' :
            raise RttiError("Cannot get a base name for non-aggregate type `%s'" % name)
        if name[3] == 'W' :
            return name[4:]
        return name[3:]

    @property
    def typeName(self) :
        return idaapi.demangle_name('?x@@3' + self.mangledName + 'A', 0)[:-2]
    
    @property
    def isClassType(self) :
        marker = self.mangledName[:3]
        return marker in ('?AU', '?AV')

    # ".?AV", ".PAV", ".?AU", ".PAU", ".?AT", ".PAT" ".?AW" ".PAX"
    typeNameMarkers = (0x56413F2E, 0x5641502E, 0x55413F2E, 0x5541502E, 0x54413F2E, 0x5441502E, 0x57413F2E, 0x5841502E)

    @staticmethod
    def isValid(ea) :
        """
        See if this looks like a type descriptor.
        """
        # FIXME: 64-bit compatibility
        if idaapi.get_full_long(ea) == 0 :
            return False
        if idaapi.get_full_long(ea + 4) != 0 :
            return False
        if idaapi.get_full_long(ea + 8) not in TypeDescriptor.typeNameMarkers :
            return False
        try :
            name = TypeDescriptor.makeName(ea)
        except :
            return False
        return True

    @staticmethod
    def makeName(ea) :
        locName = '??_R0' + getAsciiz(ea + 9) + '@8'
        if idaapi.demangle_name(locName, 0) == '' :
            raise RttiError("%08X: Location name failed to properly demangle: `%s'" % (ea, locName))
        return locName

    @staticmethod
    def isDefined(ea) :
        flags = idaapi.getFlags(ea)
        if not idc.isStruct(flags) :
            return False
        if not idc.isHead(flags) :
            return False
        if idaapi.get_name(idaapi.BADADDR, ea) != TypeDescriptor.makeName(ea) :
            return False
        return True

    @staticmethod
    def define(ea) :
        if TypeDescriptor.isDefined(ea) :
            return
        if not TypeDescriptor.isValid(ea) :
            raise RttiError("%08X: This doesn't look like a TypeDescriptor." % ea)

        # FIXME: 64-bit compatibility
        mangledName = getAsciiz(ea + 8)

        # Define data in DB
        structLength = 8 + len(mangledName) + 1
        idaapi.do_unknown_range(ea, structLength, idaapi.DOUNK_DELNAMES)
        idaapi.doStruct(ea, structLength, idaapi.get_struc_id("_TypeDescriptor"))
        idaapi.set_name(ea, TypeDescriptor.makeName(ea), 0)

    @staticmethod
    def findAll(searchBounds) :
        """
        Locate any candidates for a type descriptor object.
        Detected by the pattern: {pointer} {0} ".?AV"
        """

        results = []

        ea = searchBounds[0]
        lastEa = searchBounds[1] - 8
        while ea < lastEa :
            # if (ea & 0x1FFF) == 0 : print "At %08x" % ea
            if TypeDescriptor.isValid(ea) :
                # print "Found candidate @%08x" % (ea)
                results.append(ea)
                ea += 8
            ea += 4
        return results

#
# _s__RTTIClassHierarchyDescriptor handling.
#

class ClassHierarchyDescriptor :
    """
    """
    
    def __init__(self, ea) :
        self.ea = ea
        self.cachedBaseList = None
        ClassHierarchyDescriptor.define(ea)

    def __eq__(self, other) :
        if type(other) is not type(self) :
            return False
        return self.ea == other.ea

    def __ne__(self, other) :
        return not self.__eq__(other)

    def __str__(self) :
        td = self.baseClassArray[0].typeDescriptor
        return "%08X: RTTI Class Hierarchy Descriptor for `%s'" % (self.ea, td.typeName)

    @property
    def attributes(self) :
        return ClassHierarchyDescriptor.__attributes(self.ea)

    @property
    def isMultipleInheritance(self) :
        return (self.attributes & 1) != 0

    @property
    def isVirtualInheritance(self) :
        return (self.attributes & 2) != 0

    @property
    def baseClassCount(self) :
        return ClassHierarchyDescriptor.__baseClassCount(self.ea)

    @property
    def baseClassArray(self) :
        return BaseClassArray(
                ClassHierarchyDescriptor.__baseClassArrayPtr(self.ea),
                ClassHierarchyDescriptor.__baseClassCount(self.ea))

    @staticmethod
    def __attributes(ea) : return idaapi.get_full_long(ea + 4)
    @staticmethod
    def __baseClassCount(ea) : return idaapi.get_full_long(ea + 8)
    @staticmethod
    def __baseClassArrayPtr(ea) : return idaapi.get_full_long(ea + 12)

    @staticmethod
    def isValid(ea) :
        if idaapi.get_full_long(ea) != 0 :
            return False
        attrs = ClassHierarchyDescriptor.__attributes(ea)
        if attrs > 3 :
            return False
        baseCount = ClassHierarchyDescriptor.__baseClassCount(ea)
        if baseCount > 1024 :
            return False
        # TODO: add sanity checks.
        return True

    @staticmethod
    def isDefined(ea) :
        flags = idaapi.getFlags(ea)
        if not idc.isStruct(flags) :
            return False
        if not idc.isHead(flags) :
            return False
        # TODO: verify the actual struct type.
        return True

    @staticmethod
    def define(ea) :
        if ClassHierarchyDescriptor.isDefined(ea) :
            return
        if not ClassHierarchyDescriptor.isValid(ea) :
            raise RttiError("%08X: Doesn't look like a correct ClassHierarchyDescriptor" % ea)

        strid = idaapi.get_struc_id('_s__RTTIClassHierarchyDescriptor')
        size = idaapi.get_struc_size(strid)
        idaapi.do_unknown_range(ea, size, idaapi.DOUNK_DELNAMES)
        idaapi.doStruct(ea, size, strid)

        bca = BaseClassArray(
                ClassHierarchyDescriptor.__baseClassArrayPtr(ea),
                ClassHierarchyDescriptor.__baseClassCount(ea))

        # Entry 0 describes the class itself => I can find out the class name.
        idaapi.set_name(ea, '??_R3' + bca[0].typeDescriptor.baseMangledName + '8', 0)

#
# Base Class Array handling.
#

class BaseClassArray :
    def __init__(self, ea, count) :
        self.ea = ea
        self.count = count
        BaseClassArray.define(ea, count)
    
    def __len__(self) :
        return self.count
    
    def __getitem__(self, index) :
        if index < 0 or index >= self.count :
            raise IndexError('Index too large')

        return BaseClassDescriptor(idaapi.get_full_long(self.ea + index * 4))

    def __str__(self) :
        return "%08X: RTTI Base Class Array"

    def parse(self, index = 0) :
        """
        Parse the class hierarchy, returning a tree of Node objects.
        """
        bcd = self[index]
        basesCount = bcd.containedBasesCount
        limit = index + basesCount
        index += 1
        while index <= limit :
            parent = self.parse(index)
            bcd.baseClasses.append(parent)
            index += parent.containedBasesCount + 1
        return bcd

    @staticmethod
    def define(ea, count) :
        # TODO: sanity checks
        
        idaapi.do_unknown_range(ea, count * 4, idaapi.DOUNK_DELNAMES)
        idaapi.doDwrd(ea, 4)
        idaapi.do_data_ex(ea, idaapi.getFlags(ea), count * 4, idaapi.BADADDR)
        
        # Entry 0 describes the class itself => I can find out the class name.
        bcd = BaseClassDescriptor(idaapi.get_full_long(ea))
        idaapi.set_name(ea, '??_R2' + bcd.typeDescriptor.baseMangledName + '8', 0)

        i = 1
        while i < count :
            bcd = BaseClassDescriptor(idaapi.get_full_long(ea + i * 4))
            i += 1

#
# _s__RTTIBaseClassDescriptor2 handling.
# TODO: handle compiler version variations; seems like older ones miss some members.
#

def mangleNumber(num) :
    if num == 0 :
        return '@'
    sign = ''
    if num < 0 :
        sign = '?'
        num = -num
    numtext = hex(num).upper()[2:-1]
    numtext = sign + numtext.translate(string.maketrans('0123456789ABCDEF', 'ABCDEFGHIJKLMNOP')) + '@'
    return numtext

class BaseClassDescriptor :
    """
    """

    def __init__(self, ea) :
        self.ea = ea
        self.baseClasses = []
        BaseClassDescriptor.define(ea)

    def __eq__(self, other) :
        if type(other) is not type(self) :
            return False
        return self.ea == other.ea

    def __ne__(self, other) :
        return not self.__eq__(other)

    def __str__(self) :
        pmd = self.where
        return "%08X: RTTI Base Class Descriptor for `%s' at (%d,%d,%d,%d)" % (self.ea, self.typeDescriptor.typeName, pmd.mdisp, pmd.pdisp, pmd.vdisp, self.attributes)

    @property
    def typeDescriptor(self) :
        return TypeDescriptor(BaseClassDescriptor.__typeDescriptorPtr(self.ea))

    @property
    def containedBasesCount(self) :
        return BaseClassDescriptor.__containedBasesCount(self.ea)

    @property
    def where(self) :
        return BaseClassDescriptor.__where(self.ea)

    @property
    def attributes(self) :
        return BaseClassDescriptor.__attributes(self.ea)

    @property
    def isVersion2(self) :
        return (self.attributes & 0x40) != 0

    @property
    def classHierarchyDescriptor(self) :
        if not self.isVersion2 :
            raise NotImplementedError('No Class Hierarchy Descriptor reference available in V1 structures.')
        return ClassHierarchyDescriptor(BaseClassDescriptor.__v2ChdPtr(self.ea))

    @staticmethod
    def __typeDescriptorPtr(ea) : return idaapi.get_full_long(ea)
    @staticmethod
    def __containedBasesCount(ea) : return idaapi.get_full_long(ea + 4)
    @staticmethod
    def __where(ea) : return PMD(getInt32(ea + 8), getInt32(ea + 12), getInt32(ea + 16))
    @staticmethod
    def __attributes(ea) : return idaapi.get_full_long(ea + 20)
    @staticmethod
    def __v2ChdPtr(ea) : return idaapi.get_full_long(ea + 24)

    @staticmethod
    def isDefined(ea) :
        flags = idaapi.getFlags(ea)
        if not idc.isStruct(flags) :
            return False
        if not idc.isHead(flags) :
            return False
        # TODO: verify the actual struct type.
        return True

    @staticmethod
    def define(ea) :
        if BaseClassDescriptor.isDefined(ea) :
            return

        td = TypeDescriptor(BaseClassDescriptor.__typeDescriptorPtr(ea))

        attrs = BaseClassDescriptor.__attributes(ea)
        if attrs != 0 and attrs != 0x40 :
            print '%08X: Suspicious attributes value: %08X' % (ea, attrs)
            # raise RttiError('%08X: Suspicious attributes value: %08X' % (ea, attrs))
        isV2 = (attrs & 0x40) != 0
        if isV2 :
            strid = idaapi.get_struc_id('_s__RTTIBaseClassDescriptor2')
        else :
            strid = idaapi.get_struc_id('_s__RTTIBaseClassDescriptor')
        size = idaapi.get_struc_size(strid)
        idaapi.do_unknown_range(ea, size, idaapi.DOUNK_DELNAMES)
        idaapi.doStruct(ea, size, strid)

        pmd = BaseClassDescriptor.__where(ea)
        name = '??_R1'
        name += mangleNumber(pmd.mdisp)
        name += mangleNumber(pmd.pdisp)
        name += mangleNumber(pmd.vdisp)
        name += mangleNumber(attrs)
        name += td.baseMangledName + '8'
        idaapi.set_name(ea, name, 0)

        if isV2 :
            ClassHierarchyDescriptor.define(BaseClassDescriptor.__v2ChdPtr(ea))

#
# _s__RTTICompleteObjectLocator handling.
#

class CompleteObjectLocator :
    """
    The CompleteObjectLocator structure allows compiler to find 
    the location of the complete object from a specific vftable pointer 
    (since a class can have several of them).
    """

    def __init__(self, ea) :
        self.ea = ea
        CompleteObjectLocator.define(ea)

    def __eq__(self, other) :
        if type(other) is not type(self) :
            return False
        return self.ea == other.ea

    def __ne__(self, other) :
        return not self.__eq__(other)

    def __str__(self) :
        return '%08X: RTTI Complete Object Locator' % (self.ea)

    @property
    def vftableOffset(self) :
        return idaapi.get_full_long(self.ea + 4)

    @property
    def ctorDispOffset(self) :
        return idaapi.get_full_long(self.ea + 8)

    @property
    def typeDescriptor(self) :
        at = idaapi.get_full_long(self.ea + 12)
        return TypeDescriptor(at)

    @property
    def classHierarchyDescriptor(self) :
        at = idaapi.get_full_long(self.ea + 16)
        return ClassHierarchyDescriptor(at)

    @staticmethod
    def isValid(ea) :
        # Signature field must be zero
        if idaapi.get_full_long(ea) != 0 :
            # print "Signature fail"
            return False
        # At offset 12, there should be a pointer to a valid TypeDescriptor
        tdPtr = idaapi.get_full_long(ea + 12)
        if not TypeDescriptor.isValid(tdPtr) :
            # print "TD fail"
            return False
        # At offset 16, there should be a pointer to a valid ClassHierarchyDescriptor
        chdPtr = idaapi.get_full_long(ea + 16)
        if not ClassHierarchyDescriptor.isValid(chdPtr) :
            # print "CHD fail"
            return False
        return True

    @staticmethod
    def isDefined(ea) :
        flags = idaapi.getFlags(ea)
        if not idc.isStruct(flags) :
            return False
        if not idc.isHead(flags) :
            return False
        # TODO: verify the actual struct type.
        return True

    @staticmethod
    def define(ea) :
        if CompleteObjectLocator.isDefined(ea) :
            return
        if not CompleteObjectLocator.isValid(ea) :
            raise RttiError("%08X: doesn't look like a correct CompleteObjectLocator" % (ea))

        # Ensure referenced structs are defined.
        # An exception will be thrown if something goes wrong.
        tdPtr = idaapi.get_full_long(ea + 12)
        td = TypeDescriptor(tdPtr)
        chdPtr = idaapi.get_full_long(ea + 16)
        chd = ClassHierarchyDescriptor(chdPtr)

        strid = idaapi.get_struc_id('_s__RTTICompleteObjectLocator')
        size = idaapi.get_struc_size(strid)
        idaapi.do_unknown_range(ea, size, idaapi.DOUNK_DELNAMES)
        idaapi.doStruct(ea, size, strid)
        
        if chd.isMultipleInheritance :
            if chd.isVirtualInheritance :
                print '%08X: Cannot handle virtual inheritance yet.' % (ea)
            else :
                print '%08X: Cannot handle multiple inheritance yet.' % (ea)
        else :
            idaapi.set_name(ea, '??_R4' + td.baseMangledName + '6B@', 0)

#
# Integrated scanner
#

def scanRtti() :
    dataBounds = getSegBoundaries(".data")
    rdataBounds = getSegBoundaries(".rdata")
    if dataBounds is None :
        print "No .data section found. Cannot continue."
        return False
    
    print "Scanning for TypeDescriptors (might take a while)..."
    tds = TypeDescriptor.findAll(dataBounds)
    print "Found %d descriptor(s)." % len(tds)

    print "Defining TypeDescriptors..."
    for ea in tds :
        x = TypeDescriptor(ea)
        print x
    
    print "Scanning TypeDescriptors for CompleteObjectLocator refs..."
    cols = []
    ea = rdataBounds[0]
    lastEa = rdataBounds[1]
    while ea < lastEa :
        ptr = idaapi.get_full_long(ea)
        if (dataBounds[0] <= ptr < dataBounds[1]) and (ptr in tds) :
            # print "%08X" % ptr
            try :
                # Correct the address.
                colPtr = ea - 12
                col = CompleteObjectLocator(colPtr)
                print col
                cols.append(colPtr)
            except Exception, e:
                # print traceback.format_exc()
                pass
        ea += 4
    print "Found %d CompleteObjectLocator(s)." % len(cols)
