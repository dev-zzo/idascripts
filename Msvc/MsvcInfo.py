from Rtti import RttiInfofrom Rtti import RttiScannerRttiInfo = reload(RttiInfo)RttiScanner = reload(RttiScanner)class MsvcInfo :	def __init__(self) :		self.Rtti = RttiInfo.RttiInfo()		RttiScanner.scan(self.Rtti)		pass			pass#