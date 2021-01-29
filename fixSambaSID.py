import ldap
import ldap.sasl
import subprocess
import re
import os,sys

class SambaSIDFixer:

	def __init__(self):
		self.LDAP_SECRET1 = '/etc/lliurex-cap-secrets/ldap-master/ldap'
		self.LDAP_SECRET2 = '/etc/lliurex-secrets/passgen/ldap.secret'

	def getActualSambaSID(self):
		result = subprocess.Popen('LANG=C LANGUAGE=en net getlocalsid',stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True).communicate()[0].decode("utf-8")
		sid = re.search('SID for domain \w+ is: (.*)',result)
		if sid != None:
			sid = sid.group(1)
		return sid

	def connection_ldapi(self):
		self.auth=ldap.sasl.sasl('','EXTERNAL')
		try:
			self.connect_ldapi=ldap.initialize('ldapi:///',trace_level=0)
			self.connect_ldapi.protocol_version=3
			self.connect_ldapi.sasl_interactive_bind_s("",self.auth)
			return True
		except:
			self.connect_ldapi = None
			return False

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
			ldapbasedn = "dc=ma5,dc=lliurex,dc=net"
			self.connect_ldap.bind_s("cn=admin,"+ldapbasedn,password)
			return True
		except Exception as e:
			print ("\n\nError" + str(e) + "\n\n")
			self.connect_ldap = None
			return False

	def updateUsers(self,actualDomainSID):
		allUsers = self.connect_ldap.search_s('dc=ma5,dc=lliurex,dc=net',ldap.SCOPE_SUBTREE,attrlist=['sambaSID','objectClass'])

		for x in allUsers:
			if(x[1].has_key('sambaSID')):
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
						print (" *** Error : " , e)
						pass
		

	def run(self):
		if self.connection_ldap():
			print("True")
			actualDomainSID = self.getActualSambaSID()
			self.updateUsers(actualDomainSID)
		else:
			print("False")
			sys.exit(1)

if __name__ == '__main__':
	a = SambaSIDFixer()
	a.run()
