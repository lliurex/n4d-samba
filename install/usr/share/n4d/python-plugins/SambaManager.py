import ldap 
import ldap.sasl 
import ldap.modlist
import ast
import datetime
import subprocess
import passlib.hash
import grp
import tempfile
import shutil
import os
import os.path
import pwd
import spwd
import time
import tarfile
import random
import string

import n4d.responses
import n4d.server.core

from jinja2 import Environment
from jinja2.loaders import FileSystemLoader

BACKUP_ERROR=-10
RESTORE_ERROR=-20
LDAP_ERROR=-30
LDAP_MODIFY_S_ERROR=-40
LDAP_LLIUREX_XID_S_ERROR=-50
LDAP_OU_ERROR=-60
SLAPD_ERROR=-70
LOAD_SCHEMA_ERROR=-80
LOAD_INDEX_ERROR=-90
LOAD_BASIC_STRUCTURE_ERROR=-90
LOAD_ALL_SYSTEM_GROUPS_ERROR=-100
UPDATE_XID_COUNTER_ERROR=-110
LOAD_ADMIN_SYSTEM_USER_ERROR=-120
INSERT_ADMIN_PROFILE_ERROR=-130
INSERT_ADMIN_GROUPS_ERROR=-140
LOAD_ACL_SAMBA_EDUCATION_ERROR=-150
CHANGE_SID_ERROR=-160

class SambaManager:
	predepends = ['SlapdManager']
	def __init__(self):
		
		self.core=n4d.server.core.Core.get_core()
		
		# Vars
		self.LDAP_SECRET1 = '/etc/lliurex-cap-secrets/ldap-master/ldap'
		self.LDAP_SECRET2 = '/etc/lliurex-secrets/passgen/ldap.secret'
		self.log_path = '/var/log/n4d/samba'
		self.tpl_env = Environment(loader=FileSystemLoader('/usr/share/n4d/templates/samba'))
		self.available_acl_path = '/usr/share/n4d-ldap/available_acl/samba/'
		self.enable_acl_path = '/var/lib/n4d-ldap/enable_acl/'
	#def __init__

	def apt(self):
		pass
	#def apt
	
	def startup(self,options):
		
		self.core.set_variable("SAMBASID",self.get_local_sid())
		self.connection_ldap()

	#def startup

	def get_local_sid(self):
		
		sid=""
		try:
			p=subprocess.Popen(["net","getlocalsid"],stdout=subprocess.PIPE).communicate()[0]
			sid=p.decode("utf-8").split(":")[1].strip()
		except Exception as e:
			sid=""

		return sid

	#def get_local_sid

	def test(self):
		#pass
		return n4d.responses.build_successful_call_response()
	#def test
	
	def backup(self,folder_path='/backup/'):
		try:
			if not folder_path.endswith("/"):
				folder_path+="/"
			file_path=folder_path+get_backup_name("Samba")
			tar=tarfile.open(file_path,"w:gz")
			tar.add('/etc/samba')
			tar.add('/etc/lliurex-secrets/passgen/ldap.secret')
			tar.add('/var/lib/lliurex-folders')
			tar.close()
			#return [True,file_path]
			return n4d.responses.build_successful_call_response(file_path)
			
		except Exception as e:
			return n4d.responses.build_failed_call_response(BACKUP_ERROR)
			#return [False,str(e)]
	#def backup
	
	def restore(self,file_path=None):
		if file_path==None:
			for f in sorted(os.listdir("/backup"),reverse=True):
				if "Samba" in f:
					file_path="/backup/"+f
					break

		try:

			if os.path.exists(file_path):
				
				tmp_dir=tempfile.mkdtemp()
				tar=tarfile.open(file_path)
				tar.extractall(tmp_dir)
				tar.close()
				copy_folder = os.path.join(tmp_dir,'*')
				os.system('rsync -ax ' + copy_folder + ' /')
				os.system('chmod 600 /etc/lliurex-secrets/passgen/ldap.secret')
				os.system('smbpasswd -w $(cat /etc/lliurex-secrets/passgen/ldap.secret)')
				return n4d.responses.build_successful_call_response()
				#return [True,""]
				
		except Exception as e:
			return n4d.responses.build_failed_call_response(RESTORE_ERROR)
			#return [False,str(e)]
	#def restore

	def update_xid_counter(self,ou,new_value):
		if not self.test_ldap_connection():
			if not self.connection_ldap():
				#return {"status":False,"msg":"Connection with ldap is not created"}
				return n4d.responses.build_failed_call_response(LDAP_ERROR)
		list_entry = self.connect_ldap.search_s(ou,ldap.SCOPE_SUBTREE)

		if len(list_entry) > 0 :
			name_entry,entry = list_entry[0]
			if "x-lliurex-xid-counter" in entry:
				if len(entry['x-lliurex-xid-counter']) > 0 and int(entry['x-lliurex-xid-counter'][0]) < int(new_value):
					aux_entry = entry.copy()
					aux_entry['x-lliurex-xid-counter'] = [str(new_value)]
					aux_entry=self.core.get_plugin("SlapdManager").str_to_bytes(aux_entry)
					mod_entry = ldap.modlist.modifyModlist(entry,aux_entry)
					try:
						self.connect_ldap.modify_s(name_entry,mod_entry)
					except Exception as e:
						return n4d.responses.build_failed_call_response(LDAP_MODIFY_S_ERROR)
						#return [False,str(e.message)]
				return n4d.responses.build_successful_call_response()
				#return [True,""]
			else:
				return n4d.responses.build_failed_call_response(LDAP_LLIUREX_XID_S_ERROR)
				#return [False,"ou " + ou + " hasn't x-lliurex-xid-counter property"]
		else:
			return n4d.responses.build_failed_call_response(LDAP_OU_ERROR)
			#return [False,"ou " + ou + " not exist"]
	#def update_xid_counter

	def load_schema(self):
		template = self.tpl_env.get_template('schemas')
		string_template = template.render()
		aux_dic = ast.literal_eval(string_template)
		for entry_name in aux_dic.keys():
			slapdp=self.core.get_plugin("SlapdManager")
			if slapdp==None:
				#return {'status':False,'msg':'This function depend on SlapdManager, but this is not installed or not working'}
				return n4d.responses.build_failed_call_response(SLAPD_ERROR)
			
			data=slapdp.str_to_bytes(aux_dic[entry_name])
			result = slapdp.load_schema(entry_name,data,True)
			if result['status']!=0:
				return n4d.responses.build_failed_call_response(LOAD_SCHEMA_ERROR)
				#return result
		#return {'status':True,'msg':'Load schema to samba'}
		return n4d.responses.build_successful_call_response()
	#def load_schema
	
	def load_index(self):
		template = self.tpl_env.get_template('index')
		string_template = template.render()
		aux_dic = ast.literal_eval(string_template)
		slapdp=self.core.get_plugin("SlapdManager")
		if slapdp==None:
			#return {'status':False,'msg':'This function depend on SlapdManager, but this is not installed or not working'}
			return n4d.responses.build_failed_call_response(SLAPD_ERROR)
		result = slapdp.update_index(aux_dic)
		if result['status']!=0:
			return n4d.responses.build_failed_call_response(LOAD_INDEX_ERROR)
			#return result
		return n4d.responses.build_successful_call_response()
		#return {'status':True,'msg':'Load index to samba'}
	#def load_index
	
	def load_basic_structure(self):
		template = self.tpl_env.get_template('basic-structure')
		environment_basic = self.core.get_variable_list(['SAMBA_DOMAIN_NAME','LDAP_BASE_DN','SAMBASID'])["return"]
		string_template = template.render(environment_basic)
		aux_dic = ast.literal_eval(string_template)
		slapdp=self.core.get_plugin("SlapdManager")
		if slapdp==None:
			#return {'status':False,'msg':'This function depend on SlapdManager, but this is not installed or not working'}
			return n4d.responses.build_failed_call_response(SLAPD_ERROR)
		data=slapdp.str_to_bytes(aux_dic)
		result = slapdp.insert_dictionary(data,i_existing=True)
		if result['status']==0:
			return n4d.responses.build_successful_call_response()
			#return {'status':True,'msg':'Load basic structure to work samba'}
		else:
			return n4d.responses.build_failed_call_response(LOAD_BASIC_STRUCTURE_ERROR)
			#return result
	#def load_basic_structure
	
	def load_all_system_groups(self,min_gid=0,max_gid=1000):
		template = self.tpl_env.get_template('system-group')
		environment_vars = self.core.get_variable_list(['LDAP_BASE_DN'])["return"]
		max_counter = 0
		for x in grp.getgrall():
			environment_vars["GROUP_NAME"] = x.gr_name
			environment_vars["GROUP_ID"] = x.gr_gid
			if x.gr_gid <= min_gid or x.gr_gid >= max_gid:
				continue
			if int(x.gr_gid) > max_counter:
				max_counter = x.gr_gid
			string_template = template.render(environment_vars)
			aux_dic = ast.literal_eval(string_template)
			slapdp=self.core.get_plugin("SlapdManager")
			if slapdp==None:
				#return {'status':False,'msg':'This function depend on SlapdManager, but this is not installed or not working'}
				return n4d.responses.build_failed_call_response(SLAPD_ERROR)
			aux_dic=slapdp.str_to_bytes(aux_dic)
			result = slapdp.insert_dictionary(aux_dic,i_existing=True)
			if result['status']!=0:
				return n4d.responses.build_failed_call_response(LOAD_ALL_SYSTEM_GROUPS_ERROR)
				#return result
		result = self.update_xid_counter("ou=System,ou=Groups,"+environment_vars['LDAP_BASE_DN'],max_counter)
		if result["status"]==0:
			return n4d.responses.build_successful_call_response()
			#return {'status':True,'msg':'Load all groups from system'}
		else:
			return n4d.responses.build_failed_call_response(UPDATE_XID_COUNTER_ERROR)
			#return {'status':False,'msg':result[1]}
	#def load_all_system_groups

	def load_admin_system_user(self):
		template = self.tpl_env.get_template('admin-users')
		environment_vars = self.core.get_variable_list(['LDAP_BASE_DN','SAMBASID'])["return"]
		users_adm = grp.getgrnam('adm').gr_mem
		max_uid = 0
		for x in users_adm:
			user = pwd.getpwnam(x)
			environment_vars['USERNAME'] = user.pw_name
			environment_vars['USERNAME_UID'] = user.pw_uid
			if int(user.pw_uid) > max_uid:
				max_uid = int(user.pw_uid)
			environment_vars['USERHOME'] = user.pw_dir
			environment_vars['USERPASSWORD'] = "{crypt}" + spwd.getspnam(user.pw_name).sp_pwd
			environment_vars['SAMBASIDUSER'] = str(environment_vars['SAMBASID']) + "-" + str(environment_vars['USERNAME_UID'])
			string_template = template.render(environment_vars)
			aux_dic = ast.literal_eval(string_template)
			
			slapdp=self.core.get_plugin("SlapdManager")
			if slapdp==None:
				#return {'status':False,'msg':'This function depend on SlapdManager, but this is not installed or not working'}
				return n4d.responses.build_failed_call_response(SLAPD_ERROR)
			aux_dic=slapdp.str_to_bytes(aux_dic)
			result = slapd.insert_dictionary(aux_dic,i_existing=True)
			if not result['status']:
				return n4d.responses.build_failed_call_response(LOAD_ADMIN_SYSTEM_USER_ERROR)
				#return result
			aux_dn = aux_dic.keys()[0]
			result = self.insert_to_admin_profile(aux_dn,aux_dic[aux_dn]['uid'])
			if not result['status']:
				return n4d.responses.build_failed_call_response(INSERT_ADMIN_PROFILE_ERROR)
				#return result
		result = self.update_xid_counter("ou=Admins,ou=People,"+environment_vars['LDAP_BASE_DN'],max_uid)
		if result[0]:
			#return {'status':True,'msg':'Load all admin users from system'}
			return n4d.responses.build_successful_call_response()
		else:
			return n4d.responses.build_failed_call_response(UPDATE_XID_COUNTER_ERROR)
			#return {'status':False,'msg':result[1]}
	#def load_admin_system_user
	
	def load_net_admin_user(self,password=None):
		template = self.tpl_env.get_template('net-admin-user')
		
		slapdp=self.core.get_plugin("SlapdManager")
		if slapdp==None:
			#return {'status':False,'msg':'This function depend on SlapdManager, but this is not installed or not working'}
			return n4d.responses.build_failed_call_response(SLAPD_ERROR)
		environment_vars = self.core.get_variable_list(['LDAP_BASE_DN','SAMBASID'])["return"]
		environment_vars['USERPASSWORD'] = slapdp.generate_ssha_password(password).strip()
		#Ported to hashlib
		#environment_vars["NTPASSWORD"]=smbpasswd.nthash(password)
		environment_vars["NTPASSWORD"]=passlib.hash.nthash.encrypt(password).upper()
		#environment_vars["LMPASSWORD"]=smbpasswd.lmhash(password)
		environment_vars["LMPASSWORD"]=passlib.hash.lmhash.encrypt(password).upper()
		environment_vars["LASTSET"]=str(int(time.time()))
		string_template = template.render(environment_vars)
		aux_dic = ast.literal_eval(string_template)
		aux_dn = list(aux_dic.keys())[0]
		user=aux_dic[aux_dn]['uid']
		aux_dic=slapdp.str_to_bytes(aux_dic)
		
		result = slapdp.insert_dictionary(aux_dic,i_existing=True)
		if result['status']!=0:
			return n4d.responses.build_failed_call_response(LOAD_NET_ADMIN_USER_ERROR)
			#return result
		
		
		result = self.insert_to_admin_profile(aux_dn,user)
		if result['status']!=0:
			return n4d.responses.build_failed_call_response(INSERT_ADMIN_PROFILE_ERROR)
			#return result
		result = self.insert_to_admin_groups(user)
		if result['status']!=0:
			return n4d.responses.build_failed_call_response(INSERT_ADMIN_GROUPS_ERROR)
			#return result
		result = self.update_xid_counter("ou=Admins,ou=People,"+environment_vars['LDAP_BASE_DN'],1042)
		if result["status"]==0:
			#return {'status':True,'msg':'Load all admin users from system'}
			return n4d.responses.build_successful_call_response()
		else:
			return n4d.responses.build_failed_call_response(UPDATE_XID_COUNTER_ERROR)
			#return {'status':False,'msg':result[1]}
	
			
	def load_ro_admin_user(self):
		
		template=self.tpl_env.get_template("ro-admin-user")
		
		environment_vars=self.core.get_variable_list(["LDAP_BASE_DN"])["return"]
		password="".join(random.sample(string.ascii_letters+string.digits, 4))
		environment_vars["PASSWORD"]=self.core.get_plugin("SlapdManager").generate_ssha_password(password).strip()
		string_template=template.render(environment_vars)
		aux_dic=ast.literal_eval(string_template)
		aux_dic=self.core.get_plugin("SlapdManager").str_to_bytes(aux_dic)
		result=self.core.get_plugin("SlapdManager").insert_dictionary(aux_dic,i_existing=True)
		
		return n4d.responses.build_successful_call_response()
		#return result
		
		
	#def load_ro_admin_user
	
	def load_education(self):
		template = self.tpl_env.get_template('education')
		environment_vars = self.core.get_variable_list(['LDAP_BASE_DN','SAMBASID'])["return"]
		string_template = template.render(environment_vars)
		aux_dic = ast.literal_eval(string_template)
		slapdp=self.core.get_plugin("SlapdManager")
		if slapdp==None:
			#return {'status':False,'msg':'This function depend on SlapdManager, but this is not installed or not working'}
			return n4d.responses.build_failed_call_response(SLAPD_ERROR)
		aux_dic=slapdp.str_to_bytes(aux_dic)
		result = slapdp.insert_dictionary(aux_dic,i_existing=True)
		if result['status']!=0:
			return n4d.responses.build_failed_call_response(LOAD_EDUCATION_ERROR)
			#return result
		result = self.update_xid_counter("ou=Profiles,ou=Groups,"+environment_vars['LDAP_BASE_DN'],10005)
		if result["status"]==0:
			#objects['VariablesManager'].init_variable('ENABLE_NSS_LDAP',{'ENABLE_NSS_LDAP':'ENABLED'})
			self.core.set_variable('ENABLE_NSS_LDAP',"ENABLED")
			return n4d.responses.build_successful_call_response()
			#return {'status':True,'msg':'Load structure for education model'}
		else:
			return n4d.responses.build_failed_call_response(UPDATE_XID_COUNTER_ERROR)
			#return {'status':False,'msg':result[1]}
	#def load_education
	
	def configure_smb(self):
		template = self.tpl_env.get_template('smb.conf')
		
		self.core.set_variable("DEADTIME",15)
		self.core.set_variable("SAMBA_DOMAIN_NAME","lliurex")
		self.core.set_variable("NAME_SERVER_SAMBA","%h")
		
		environment_vars = self.core.get_variable_list(['SAMBA_DOMAIN_NAME','NAME_SERVER_SAMBA','DEADTIME','LDAP_BASE_DN'])["return"]
		string_template = template.render(environment_vars).encode('utf-8')
		tmp,filename=tempfile.mkstemp()
		f = open(filename,'w')
		f.writelines(string_template.decode("utf-8"))
		f.close()
		self.core.n4d_mv(filename,'/etc/samba/smb.conf')
		return n4d.responses.build_successful_call_response()
		#return {'status':True,'msg':'Configured samba'}
	#def configure_smb
	
	def load_acl_samba_education(self):
		if os.path.exists(self.available_acl_path + 'all_samba'):
			installed_link = False
			if not os.path.exists(self.enable_acl_path + '600_all_samba'):
				os.symlink(self.available_acl_path + 'all_samba',self.enable_acl_path + '600_all_samba')
		if os.path.exists(self.available_acl_path + 'subtree_students_samba'):
			installed_link = False
			if not os.path.exists(self.enable_acl_path + '400_subtree_students_samba'):
				os.symlink(self.available_acl_path + 'subtree_students_samba',self.enable_acl_path + '400_subtree_students_samba')
		result = self.core.get_plugin("SlapdManager").load_acl()
		if result['status']!=0:
			return n4d.responses.build_failed_call_response(LOAD_ACL_SAMBA_EDUCATION_ERROR)
			#return result
		return n4d.responses.build_successful_call_response()
		#return {'status':True,'msg':'Loaded acl'}
	#def load_acl_samba
	
	def update_root_password_samba(self,password):
		subprocess.Popen(['smbpasswd','-w',password],stdout=subprocess.PIPE).communicate()
		return n4d.responses.build_successful_call_response()
		#return {'status':True,'msg':'Update root password on samba database'}
	#def update_root_password_samba
	
	def insert_to_admin_profile(self,dn,uid):
		if not self.test_ldap_connection():
			if not self.connection_ldap():
				return {"status":False,"msg":"Connection with ldap is not created"}
		
		environment_vars = self.core.get_variable_list(['LDAP_BASE_DN'])["return"]
		path = "cn=admins,ou=Profiles,ou=Groups,"+  environment_vars['LDAP_BASE_DN']
		mod_list=[]
		mod=(ldap.MOD_ADD,"memberUid",str(uid))
		mod_list.append(mod)
		mod_list=self.core.get_plugin("SlapdManager").str_to_bytes(mod_list)
		for x in mod_list:
			try:
				self.connect_ldap.modify_s(path,[x])
			except ldap.ALREADY_EXISTS as e:
				pass
			except Exception as e:
				#return {'status':False,'msg':'insert_to_admin_profile error :'+ str(e)}
				return n4d.responses.build_failed_call_response(INSERT_ADMIN_PROFILE_ERROR)
		#return {'status':True,'msg':str(uid)+ 'has been added to admin profile'}
		return n4d.responses.build_successful_call_response()
	#def insert_to_admin_profile
	
	def insert_to_admin_groups(self, uid):
		if not self.test_ldap_connection():
			if not self.connection_ldap():
				return n4d.responses.build_failed_call_response(LDAP_ERROR)
				#return {"status":False,"msg":"Connection with ldap is not created"}
		environment_vars = self.core.get_variable_list(['LDAP_BASE_DN'])["return"]
		system_admin_groups = ['sudo','adm','plugdev','lpadmin','cdrom','dip','epoptes']
		for group in system_admin_groups:
			mod=(ldap.MOD_ADD,"memberUid",str(uid))
			mod=self.core.get_plugin("SlapdManager").str_to_bytes(mod)
			group_path="cn=" + group +",ou=System,ou=Groups," + environment_vars['LDAP_BASE_DN']
			try:
				self.connect_ldap.modify_s(group_path,[mod])
			except ldap.ALREADY_EXISTS as e:
				pass
			except Exception as e:
				return n4d.responses.build_failed_call_response(INSERT_ADMIN_GROUPS_ERROR)
				#return {'status':False,'msg':'insert to admin group error :'+ str(e)}	
		return n4d.responses.build_successful_call_response()
		#return {'status':True,'msg':'All ok'}

	def set_sambasid(self,sambasid):
		result = os.system('net setlocalsid ' + sambasid)
		if result == 0:
			return n4d.responses.build_successful_call_response()
			#return{'status':True,'msg': 'SID ' + str(sambasid) + ' has been set'}
		else:
			return n4d.responses.build_failed_call_response(CHANGE_SID_ERROR)
			#return{'status':False,'msg': 'SID could not change'}
	'''
		Internal Methods
	'''

	def test_ldap_connection(self):
		try:
			self.connection_ldap.search_s('',ldap.SCOPE_BASE)
			return True
		except:
			return False
	#def test_ldap_connection


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
			environment_vars = self.core.get_variable_list(['LDAP_BASE_DN'])["return"]
			self.connect_ldap.bind_s("cn=admin,"+environment_vars['LDAP_BASE_DN'],password)
			return True
		except Exception as e:
			print ("\n\nError" + str(e) + "\n\n")
			self.connect_ldap = None
			return False

	# def connection_ldap
