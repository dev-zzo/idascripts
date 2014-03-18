# Script for IDA Pro to recognise and process 
#  product identification block (aka "Rich" signatures).
# See http://ntcore.com/files/richsign.htm
#

import struct
import idc

class ProductId :
	"""
	Plain data structure to hold description of a product.
	"""
	
	def __init__(self, id, version, description, prod_version, options) :
		self.id = id
		self.version = version
		self.description = description
		self.prod_version = prod_version
		self.options = options
		pass
		
	def __str__(self) :
		if self.description is not None :
			return "Product: %s, Version: %s" % (self.description, self.prod_version)
		else :
			return "Product ID: %d, Version: %d" % (self.id, self.version)
		
	pass
# End of ProductId

__product_table = [
	ProductId( 61,  9351, "Microsoft (R) Incremental Linker", "7.00.9351", []), # ?
	
	ProductId( 15,  4035, "Microsoft (R) Macro Assembler", "7.10.4035", []),
	ProductId( 90,  4035, "Microsoft (R) Incremental Linker", "7.10.4035", []),
	ProductId( 94,  4035, "Microsoft (R) CVTRES", "7.10.4035", []),
	ProductId( 95,  4035, "Microsoft (R) Optimizing Compiler", "7.10.4035", []),
	
	ProductId(109, 40310, "Microsoft (R) Optimizing Compiler", "8.00.40310", []),
	ProductId(120, 40310, "Microsoft (R) Incremental Linker", "8.00.40310", []),
	ProductId(125, 40310, "Microsoft (R) Macro Assembler", "8.00.40310", []),
	
	# DDK 6000
	ProductId(109, 50727, "Microsoft (R) Optimizing Compiler", "8.00.50727", []),
	ProductId(120, 50727, "Microsoft (R) Incremental Linker", "8.00.50727", []),
	# ID: 123
	ProductId(124, 50727, "Microsoft (R) CVTRES", "8.00.50727", []),
	ProductId(125, 50727, "Microsoft (R) Macro Assembler", "8.00.50727", []),
	
	# MS Visual Studio 2008
	ProductId(131, 21022, "Microsoft (R) Optimizing Compiler", "9.00.21022", []), # /TC
	ProductId(132, 21022, "Microsoft (R) Optimizing Compiler", "9.00.21022", ["Cpp"]), # /TP
	ProductId(137, 21022, "Microsoft (R) Optimizing Compiler", "9.00.21022", ["LTCG"]), # /TC
	ProductId(138, 21022, "Microsoft (R) Optimizing Compiler", "9.00.21022", ["Cpp", "LTCG"]), # /TP
	# ID: 140
	ProductId(145, 21022, "Microsoft (R) Incremental Linker", "9.00.21022", []),
	# ID: 147
	ProductId(148, 21022, "Microsoft (R) CVTRES", "9.00.21022", []),
	ProductId(149, 21022, "Microsoft (R) Macro Assembler", "9.00.21022", []),
	# ID: 150
	
	# WDK 7600
	ProductId(131, 30729, "Microsoft (R) Optimizing Compiler", "9.00.30729", []), # /TC
	ProductId(132, 30729, "Microsoft (R) Optimizing Compiler", "9.00.30729", ["Cpp"]), # /TP
	ProductId(145, 30729, "Microsoft (R) Incremental Linker", "9.00.30729", []),
	ProductId(149, 30729, "Microsoft (R) Macro Assembler", "9.00.30729", []),
	
	# MS Visual Studio 2010
	ProductId(154, 30319, "Microsoft (R) CVTRES", "10.00.30319", []),
	ProductId(157, 30319, "Microsoft (R) Incremental Linker", "10.00.30319", []),
	ProductId(158, 30319, "Microsoft (R) Macro Assembler", "10.00.30319", []),
	ProductId(170, 30319, "Microsoft (R) Optimizing Compiler", "10.00.30319", []),
	ProductId(171, 30319, "Microsoft (R) Optimizing Compiler", "10.00.30319", []),
	ProductId(172, 30319, "Microsoft (R) Optimizing Compiler", "10.00.30319", []),
	ProductId(173, 30319, "Microsoft (R) Optimizing Compiler", "10.00.30319", []),
	ProductId(174, 30319, "Microsoft (R) Optimizing Compiler", "10.00.30319", ["WPO?"]),
	ProductId(175, 30319, "Microsoft (R) Optimizing Compiler", "10.00.30319", []),
	ProductId(176, 30319, "Microsoft (R) Optimizing Compiler", "10.00.30319", []),
	ProductId(177, 30319, "Microsoft (R) Optimizing Compiler", "10.00.30319", []),
	ProductId(178, 30319, "Microsoft (R) Optimizing Compiler", "10.00.30319", []),
	]

def __lookup(id, version) :
	for p in __product_table :
		if p.id == id and p.version == version :
			return p
	return ProductId(id, version, None, None, [])

def __read_u32(fh) :
	return struct.unpack('<I', fh.read(4))[0]

def decode() :
	with open(idc.GetInputFilePath(), 'rb') as fh :
		# Read the PE header offset from the MZ header.
		fh.seek(0x3C)
		pe_offset = __read_u32(fh)
		# print "PE header offset at %08X" % (pe_offset)
		fh.seek(pe_offset)
		pe_magic = __read_u32(fh)
		if pe_magic != 0x00004550 :
			print "PE header magic is invalid: expected %08x, got %08x." % (0x00004550, pe_magic)
			return None
		
		# Seek to the end of MZ header, scan for "Rich" magic.
		fh.seek(0x40)
		while fh.tell() < pe_offset :
			if __read_u32(fh) == 0x68636952 :
				records_end = fh.tell() - 4
				mask = __read_u32(fh)
				# print "Rich signature found, mask: %08X" % (mask)
				break
		else :
			print "Rich signature not found."
			return None

		# Seek to the end of MZ header, scan for "DanS" magic.
		fh.seek(0x40)
		while fh.tell() < records_end :
			d = __read_u32(fh) ^ mask
			if d == 0x536E6144 :
				# print "DanS signature found."
				fh.seek(12, os.SEEK_CUR)
				break
		else :
			print "DanS signature not found."
			return None
			
		product_list = []
		while fh.tell() < records_end :
			d = __read_u32(fh) ^ mask
			t = __read_u32(fh) ^ mask
			# print "%08X %08X" % (d, t)
			prod = __lookup(d >> 16, d & 0xFFFF)
			if prod.id == 1 :
				continue
			product_list.append(prod)
			# print prod
			
		return product_list
# End of decode()

