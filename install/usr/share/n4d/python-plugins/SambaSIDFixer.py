import ldap
import ldap.sasl
import subprocess
import re
import os
import n4d.responses
import n4d.server.core
from n4d.utils import get_backup_name,n4d_mv

class SambaSIDFixer:

	def __init__(self):
		self.LDAP_SECRET1 = '/etc/lliurex-cap-secrets/ldap-master/ldap'
		self.LDAP_SECRET2 = '/etc/lliurex-secrets/passgen/ldap.secret'
		self.basedn = 'dc=ma5,dc=lliurex,dc=net'

	def getActualSambaSID(self):
		result = subprocess.Popen('LANG=C LANGUAGE=en net getlocalsid',stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True).communicate()[0]
		sid = re.search('SID for domain \w+ is: (.*)',result.decode())
		if sid != None:
			sid = sid.group(1)
		return sid

	def connection_ldap(self):
		try:
			self.connect_ldap=ldap.initialize('ldap://localhost:389',trace_level=0)
			self.connect_ldap.protocol_version=3
			if os.path.exists(self.LDAP_SECRET1):
				f=open(self.LDAP_SECRET1)
				lines=f.readlines()
				f.close()
				password=lines[0].replace("\n","")
			elif os.path.exists(self.LDAP_SECRET2):
				f=open(self.LDAP_SECRET2)
				lines=f.readlines()
				f.close()
				password=lines[0].replace("\n","")
			else:
				self.connect_ldap = None
				return False
			self.connect_ldap.bind_s("cn=admin,"+self.basedn,password)
			return True
		except Exception as e:
			print("\n\nError" + str(e) + "\n\n")
			self.connect_ldap = None
			return False

	def updateEntries(self,actualDomainSID):
		allUsers = self.getEntriesWithSambaSid()
		for x in allUsers:
			dn = x[0]
			values = x[1]
			if values['sambaSID'][0].find(actualDomainSID) != 0:
				newSID = actualDomainSID
				if not 'sambaDomain' in values['objectClass']:
					newSID = actualDomainSID + "-" + values['sambaSID'][0].split("-")[-1]
				updateSID = [(ldap.MOD_REPLACE,'sambaSID',newSID)]
				try:
					self.connect_ldap.modify_s(dn,updateSID)
				except Exception as e:
					print(" *** Error : %s"%e)
					pass
			if values.has_key('sambaPrimaryGroupSID'):
				if values['sambaPrimaryGroupSID'][0].find(actualDomainSID) != 0:
					newPrimaryGroupSID = actualDomainSID + "-" + values['sambaPrimaryGroupSID'][0].split("-")[-1]
					updateSID = [(ldap.MOD_REPLACE,'sambaPrimaryGroupSID',newPrimaryGroupSID)]
					try:
						self.connect_ldap.modify_s(dn,updateSID)
					except Exception as e:
						print(" *** Error : %s"%e)
						pass
	
	def getEntriesWithSambaSid(self):
		listEntries = []
		allEntries = self.connect_ldap.search_s(self.basedn,ldap.SCOPE_SUBTREE,attrlist=['sambaSID','objectClass','sambaPrimaryGroupSID'])
		for x in allEntries:
			#if(x[1].has_key('sambasid')):
			if('sambasid'in x[1].keys()):
				listEntries.append(x)
		return listEntries

	def isNeedFixIt(self):
		listEntries = self.getEntriesWithSambaSid()
		listSambaSID = {}
		for x in listEntries:
			try:
				values = x[1]
				dn = values['sambaSID'][0]
				dnsplited = dn.split('-')
				if len(dnsplited) > 5 :
					if not 'sambaDomain' in values['objectClass']:
						dn = "-".join(dnsplited[:-1])
				listSambaSID[dn] = 1
			except Exception as e:
				print("IsNeedFixIt Error: {}".format(e))

		if  len(listSambaSID.keys()) > 1:
			return True
		else:
			return False

	def run(self):
		self.connection_ldap()
		if self.isNeedFixIt():
			actualDomainSID = self.getActualSambaSID()
			self.updateEntries(actualDomainSID)
			print("[SambaSIDFixer] : Fixed SambaSid ")
			#return [True,"SambaSID inconsistente. Se han unificado todos los sambaSID del dominio"]
			return n4d.responses.build_successful_call_response("SambaSID inconsistente. Se han unificado todos los sambaSID del dominio")
		#return [False,"SambaSID are ok"]
		return n4d.responses.build_failed_call_response(-1,"SambaSID are ok")

	def n4d_cron(self,minutes):
		remainder = minutes % 480
		result = minutes / 480
		if minutes == 10 or ( remainder == 0 and result > 0 ):
			self.run()
