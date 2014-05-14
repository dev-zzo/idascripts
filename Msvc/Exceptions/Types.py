import idc

id = idc.GetStrucIdByName("_s_ThrowInfo")
if id == 4294967295 :
	print "Defining _s_ThrowInfo struct."
	id = idc.AddStrucEx(-1, "_s_ThrowInfo", 0);
	idc.AddStrucMember(id, "attributes",	0,	0x20000400,	-1,	4);
	idc.AddStrucMember(id, "pmfnUnwind",	0X4,	0x20500400,	-1,	4,	0XFFFFFFFF,	0,	0x000002);
	idc.AddStrucMember(id, "pForwardCompat",	0X8,	0x20500400,	-1,	4,	0XFFFFFFFF,	0,	0x000002);
	idc.AddStrucMember(id, "pCatchableTypeArray",	0XC,	0x20500400,	-1,	4,	0XFFFFFFFF,	0,	0x000002);

id = idc.GetStrucIdByName("_s_CatchableType")
if id == 4294967295 :
	print "Defining _s_CatchableType struct."
	id = idc.AddStrucEx(-1, "_s_CatchableType", 0);
	idc.AddStrucMember(id, "properties",	0,	0x20000400,	-1,	4);
	idc.AddStrucMember(id, "pType",	0X4,	0x20500400,	-1,	4,	0XFFFFFFFF,	0,	0x000002);
	idc.AddStrucMember(id, "mdisp",	0X8,	0x20200400,	-1,	4);
	idc.AddStrucMember(id, "pdisp",	0XC,	0x20200400,	-1,	4);
	idc.AddStrucMember(id, "vdisp",	0X10,	0x20200400,	-1,	4);
	idc.AddStrucMember(id, "sizeOrOffset",	0X14,	0x20000400,	-1,	4);
	idc.AddStrucMember(id, "copyFunction",	0X18,	0x20500400,	-1,	4,	0XFFFFFFFF,	0,	0x000002);

id = idc.GetStrucIdByName("_s_CatchableTypeArray")
if id == 4294967295 :
	print "Defining _s_CatchableTypeArray struct."
	id = idc.AddStrucEx(-1, "_s_CatchableTypeArray", 0);
	idc.AddStrucMember(id, "nCatchableTypes",	0,	0x20000400,	-1,	4);
	idc.AddStrucMember(id, "arrayOfCatchableTypes",	0X4,	0x25500400,	-1,	0,	0XFFFFFFFF,	0,	0x000002);

id = idc.GetStrucIdByName("_s_FuncInfo")
if id == 4294967295 :
	print "Defining _s_FuncInfo struct."
	id = idc.AddStrucEx(-1, "_s_FuncInfo", 0);
	# VC9 version
	idc.AddStrucMember(id, "magicNumberFlags",	0,	0x20000400,	-1,	4);
	idc.AddStrucMember(id, "maxState",	0X4,	0x20200400,	-1,	4);
	idc.AddStrucMember(id, "pUnwindMap",	0X8,	0x20500400,	-1,	4,	0XFFFFFFFF,	0,	0x000002);
	idc.AddStrucMember(id, "nTryBlocks",	0XC,	0x20200400,	-1,	4);
	idc.AddStrucMember(id, "pTryBlockMap",	0X10,	0x20500400,	-1,	4,	0XFFFFFFFF,	0,	0x000002);
	idc.AddStrucMember(id, "nIPMapEntries",	0X14,	0x20200400,	-1,	4);
	idc.AddStrucMember(id, "pIPtoStateMap",	0X18,	0x20500400,	-1,	4,	0XFFFFFFFF,	0,	0x000002);
	idc.AddStrucMember(id, "pESTypeList",	0X1C,	0x20500400,	-1,	4,	0XFFFFFFFF,	0,	0x000002);
	idc.AddStrucMember(id, "EHFlags",	0X20,	0x20200400,	-1,	4);

id = idc.GetStrucIdByName("_s_UnwindMapEntry")
if id == 4294967295 :
	print "Defining _s_UnwindMapEntry struct."
	id = idc.AddStrucEx(-1, "_s_UnwindMapEntry", 0);
	# VC9 version
	idc.AddStrucMember(id, "toState",	0,	0x20200400,	-1,	4);
	idc.AddStrucMember(id, "action",	0X4,	0x20500400,	-1,	0,	0XFFFFFFFF,	0,	0x000002);

id = idc.GetStrucIdByName("_s_TryBlockMapEntry")
if id == 4294967295 :
	print "Defining _s_TryBlockMapEntry struct."
	id = idc.AddStrucEx(-1, "_s_TryBlockMapEntry", 0);
	# VC9 version
	idc.AddStrucMember(id, "tryLow",	0,	0x20200400,	-1,	4);
	idc.AddStrucMember(id, "tryHigh",	0X4,	0x20200400,	-1,	4);
	idc.AddStrucMember(id, "catchHigh",	0X8,	0x20200400,	-1,	4);
	idc.AddStrucMember(id, "nCatches",	0XC,	0x20200400,	-1,	4);
	idc.AddStrucMember(id, "pHandlerArray",	0X10,	0x20500400,	-1,	0,	0XFFFFFFFF,	0,	0x000002);

id = idc.GetStrucIdByName("_s_HandlerType")
if id == 4294967295 :
	print "Defining _s_HandlerType struct."
	id = idc.AddStrucEx(-1, "_s_HandlerType", 0);
	# VC9 version
	idc.AddStrucMember(id, "adjectives",	0,	0x20000400,	-1,	4);
	idc.AddStrucMember(id, "pType",	0X4,	0x20500400,	-1,	0,	0XFFFFFFFF,	0,	0x000002);
	idc.AddStrucMember(id, "dispCatchObj",	0X8,	0x20000400,	-1,	4);
	idc.AddStrucMember(id, "addressOfHandler",	0XC,	0x20500400,	-1,	0,	0XFFFFFFFF,	0,	0x000002);
	
