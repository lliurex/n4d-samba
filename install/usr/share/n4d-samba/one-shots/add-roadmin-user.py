#!/usr/bin/env python

import xmlrpclib
import string
import random
import hashlib
import base64
import sys

from jinja2 import Environment
from jinja2.loaders import FileSystemLoader


c=xmlrpclib.ServerProxy("https://localhost:9779")

def read_n4d_key():
	
	try:
		f=open("/etc/n4d/key")
		line=f.readline().strip("\n")
		f.close()
	except:
		line=None
	return line
	
#def read_n4d_key


def generate_ssha_password():

	chars=string.letters + string.digits
	length=16
	
	salt = ""
	for i in range(int(length)):
		salt += random.choice(chars)

	password="".join(random.sample(string.letters+string.digits, 4))
	ssh_pwd="{SSHA}" + base64.encodestring(hashlib.sha1(str(password) + salt).digest() + salt)
	
	return ssh_pwd
		
#def generate_ssha_password	
	

def get_roadmin_dic():

	global c

	env = Environment(loader=FileSystemLoader('/usr/share/n4d/templates/samba'))
	template=env.get_template("ro-admin-user")
	
	vars=c.get_variable_list("","VariablesManager",["LDAP_BASE_DN"])
	vars["PASSWORD"]=generate_ssha_password().strip("\n")
	
	str_template=template.render(vars).encode("utf-8")
	exec("ro_dic="+str_template)
	
	return ro_dic
	
#def get_roadmin_dic

n4d_key=read_n4d_key()

if n4d_key==None:
	print("* [!] Error reading n4d key [!]")
	sys.exit(1)
roadmin=get_roadmin_dic()

print("* Adding roadmin user...")
c.insert_dictionary(n4d_key,"SlapdManager",roadmin)





