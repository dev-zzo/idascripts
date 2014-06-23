import idc
import idaapi
from IDAHacks import *

class RttiError(Exception) :
    def __init__(self, msg) :
        self.msg = msg
    def __str__(self) :
        return self.msg

class PMD :
    def __init__(self, mdisp, pdisp, vdisp) :
        self.mdisp = mdisp
        self.pdisp = pdisp
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
        if not TypeDescriptor.isDefined(ea) :
            TypeDescriptor.define(ea)
    
    def __eq__(self, other) :
        # There won't be two identical type descriptors.
        if type(other) is not type(self) :
            return False
        return self.ea == other.ea

    def __ne__(self, other) :
        return not self.eq(other)

    def __str__(self) :
        return "RTTI Type Descriptor for `%s'" % (self.typeName)

    @property
    def mangledName(self) :
        return getAsciiz(self.ea + 9)

    @property
    def baseMangledName(self) :
        name = self.mangledName
        if name[:2] != '.?A' :
            raise RttiError("Cannot get a base name for non-aggregate type `%s'" % name)
        if name[3] == 'W' :
            return name[5:]
        return name[4:]

    @property
    def typeName(self) :
        return idaapi.demangle_name('?x@@3' + self.mangledName + 'A', 0)[:-2]
    
    # ".?AV", ".PAV", ".?AU", ".PAU", ".?AT", ".PAT" ".?AW"
    typeNameMarkers = (0x56413F2E, 0x5641502E, 0x55413F2E, 0x5541502E, 0x54413F2E, 0x5441502E, 0x57413F2E)
    
    @staticmethod
    def isTypeDescriptor(ea) :
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
        return True
    
    @staticmethod
    def isDefined(ea) :
        # TODO: actually verify the data is properly defined in IDB.
        return False

    @staticmethod
    def define(ea) :
        # TODO: sanity checks
        if not TypeDescriptor.isTypeDescriptor(ea) :
            raise RttiError("This doesn't look like a type descriptor.")
        
        # FIXME: 64-bit compatibility
        mangledName = getAsciiz(ea + 8)

        # Use the mangled name.
        locName = '??_R0' + mangledName[1:] + '@8'
        if idaapi.demangle_name(locName, 0) == '' :
            raise RttiError("Location name failed to properly demangle: `%s'" % locName)

        # Define data in DB
        structLength = 8 + len(mangledName) + 1
        idaapi.do_unknown_range(ea, structLength, idaapi.DOUNK_DELNAMES)
        idaapi.doStruct(ea, structLength, idaapi.get_struc_id("_TypeDescriptor"))
        idaapi.set_name(ea, locName, 0)

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
            if TypeDescriptor.isTypeDescriptor(ea) :
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

    @property
    def attributes(self) :
        return idaapi.get_full_long(self.ea + 4)

    @property
    def isMultipleInheritance(self) :
        return (self.attributes & 1) != 0

    @property
    def isVirtualInheritance(self) :
        return (self.attributes & 2) != 0

    @property
    def baseClassCount(self) :
        return idaapi.get_full_long(self.ea + 8)

    @property
    def baseClassDescriptor(self) :
        # FIXME: 64-bit compatibility
        # Try caching the result...
        if self.cachedBaseList is None :
            baseArrayEa = idaapi.get_full_long(self.ea + 12)
            self.cachedBaseList = [BaseClassDescriptor(bcdEa) for bcdEa in range(baseArrayEa, baseArrayEa + self.baseClassCount * 4, 4)]
        return self.cachedBaseList

    @staticmethod
    def isDefined(ea) :
        # TODO: actually verify the data is properly defined in IDB.
        return False

    @staticmethod
    def define(ea) :
        strid = idaapi.get_struc_id('_s__RTTIClassHierarchyDescriptor')
        size = idaapi.get_struc_size(strid)
        idaapi.do_unknown_range(ea, size, idaapi.DOUNK_DELNAMES)
        idaapi.doStruct(ea, size, strid)
        # TODO: name the struct.
        # ??_R3 + ???
    
        baseCount = idaapi.get_full_long(ea + 8)
        if baseCount == 0 or baseCount > 256 :
            raise RttiError('Bogus base class count value: %d' % baseCount)
        
        # FIXME: 64-bit compatibility
        baseArrayEa = idaapi.get_full_long(ea + 12)
        idaapi.do_unknown_range(baseArrayEa, baseCount * 4, idaapi.DOUNK_DELNAMES)
        idaapi.doDwrd(baseArrayEa, 4)
        idaapi.do_data_ex(baseArrayEa, idaapi.getFlags(baseArrayEa), idaapi.get_item_size(baseArrayEa) * baseCount, BADADDR)
        # TODO: name the array

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

    @property
    def typeDescriptor(self) :
        td = idaapi.get_full_long(self.ea)
        return TypeDescriptor(td)

    @property
    def containedBasesCount(self) :
        return idaapi.get_full_long(self.ea + 4)

    @property
    def where(self) :
        return PMD(getInt32(self.ea + 8), getInt32(self.ea + 12), getInt32(self.ea + 16))

    @property
    def attributes(self) :
        return idaapi.get_full_long(self.ea + 20)

    @property
    def classHierarchyDescriptor(self) :
        chd = idaapi.get_full_long(self.ea + 24)
        return ClassHierarchyDescriptor(chd)
        
    @staticmethod
    def define(ea) :
        # TODO: fix compiler variations.
        strid = idaapi.get_struc_id('_s__RTTIBaseClassDescriptor2')
        size = idaapi.get_struc_size(strid)
        idaapi.do_unknown_range(ea, size, idaapi.DOUNK_DELNAMES)
        idaapi.doStruct(ea, size, strid)
        
        name = "??_R1"
        name += mangleNumber(getInt32(ea + 8))
        name += mangleNumber(getInt32(ea + 12))
        name += mangleNumber(getInt32(ea + 16))
        name += mangleNumber(idaapi.get_full_long(ea + 20))
        name += TypeDescriptor(idaapi.get_full_long(ea)).baseMangledName + "8"
        idaapi.set_name(ea, name, 0)

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
    def define(ea) :
        strid = idaapi.get_struc_id('_s__RTTICompleteObjectLocator')
        size = idaapi.get_struc_size(strid)
        idaapi.do_unknown_range(ea, size, idaapi.DOUNK_DELNAMES)
        idaapi.doStruct(ea, size, strid)
        pass

