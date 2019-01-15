import ldap 
import ldap.sasl 
import ldap.modlist
import ast
import datetime
import smbpasswd
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

from jinja2 import Environment
from jinja2.loaders import FileSystemLoader

class SambaManager:
	predepends = ['VariablesManager','SlapdManager']
	def __init__(self):
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
		objects["VariablesManager"].init_variable('SAMBASID')
		self.connection_ldap()

	#def startup
	
	def test(self):
		pass
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
			return [True,file_path]
			
		except Exception as e:
			return [False,str(e)]
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
				return [True,""]
				
		except Exception as e:
				
			return [False,str(e)]
	#def restore

	def update_xid_counter(self,ou,new_value):
		if not self.test_ldap_connection():
			if not self.connection_ldap():
				return {"status":False,"msg":"Connection with ldap is not created"}
		
		list_entry = self.connect_ldap.search_s(ou,ldap.SCOPE_SUBTREE)
		if len(list_entry) > 0 :
			name_entry,entry = list_entry[0]
			if entry.has_key('x-lliurex-xid-counter'):
				if len(entry['x-lliurex-xid-counter']) > 0 and int(entry['x-lliurex-xid-counter'][0]) < int(new_value):
					aux_entry = entry.copy()
					aux_entry['x-lliurex-xid-counter'] = [str(new_value)]
					mod_entry = ldap.modlist.modifyModlist(entry,aux_entry)
					try:
						self.connect_ldap.modify_s(name_entry,mod_entry)
					except Exception as e:
						return [False,str(e.message)]
				return [True,""]
			else:
				return [False,"ou " + ou + " hasn't x-lliurex-xid-counter property"]
		else:
			return [False,"ou " + ou + " not exist"]
	#def update_xid_counter

	def load_schema(self):
		template = self.tpl_env.get_template('schemas')
		string_template = template.render().encode('utf-8')
		aux_dic = ast.literal_eval(string_template)
		for entry_name in aux_dic.keys():
			if not objects.has_key('SlapdManager'):
				return {'status':False,'msg':'This function depend on SlapdManager, but this is not installed or not working'}
			result = objects['SlapdManager'].load_schema(entry_name,aux_dic[entry_name],True)
			if not result['status']:
				return result
		return {'status':True,'msg':'Load schema to samba'}
	#def load_schema
	
	def load_index(self):
		template = self.tpl_env.get_template('index')
		string_template = template.render().encode('utf-8')
		aux_dic = ast.literal_eval(string_template)
		if not objects.has_key('SlapdManager'):
			return {'status':False,'msg':'This function depend on SlapdManager, but this is not installed or not working'}
		result = objects['SlapdManager'].update_index(aux_dic)
		if not result['status']:
			return result
		return {'status':True,'msg':'Load index to samba'}
	#def load_index
	
	def load_basic_structure(self):
		template = self.tpl_env.get_template('basic-structure')
		if  objects.has_key("VariablesManager"):
			environment_basic = objects["VariablesManager"].get_variable_list(['SAMBA_DOMAIN_NAME','LDAP_BASE_DN','SAMBASID'])
		string_template = template.render(environment_basic).encode('utf-8')
		aux_dic = ast.literal_eval(string_template)
		if not objects.has_key('SlapdManager'):
			return {'status':False,'msg':'This function depend on SlapdManager, but this is not installed or not working'}
		result = objects['SlapdManager'].insert_dictionary(aux_dic,i_existing=True)
		if result['status']:
			return {'status':True,'msg':'Load basic structure to work samba'}
		else:
			return result
	#def load_basic_structure
	
	def load_all_system_groups(self,min_gid=None,max_gid=1000):
		template = self.tpl_env.get_template('system-group')
		if  objects.has_key("VariablesManager"):
			environment_vars = objects["VariablesManager"].get_variable_list(['LDAP_BASE_DN'])
		max_counter = 0
		for x in grp.getgrall():
			environment_vars["GROUP_NAME"] = x.gr_name
			environment_vars["GROUP_ID"] = x.gr_gid
			if x.gr_gid <= min_gid or x.gr_gid >= max_gid:
				continue
			if int(x.gr_gid) > max_counter:
				max_counter = x.gr_gid
			string_template = template.render(environment_vars).encode('utf-8')
			aux_dic = ast.literal_eval(string_template)
			if not objects.has_key('SlapdManager'):
				return {'status':False,'msg':'This function depend on SlapdManager, but this is not installed or not working'}
			result = objects['SlapdManager'].insert_dictionary(aux_dic,i_existing=True)
			if not result['status']:
				return result
		result = self.update_xid_counter("ou=System,ou=Groups,"+environment_vars['LDAP_BASE_DN'],max_counter)
		if result[0]:
			return {'status':True,'msg':'Load all groups from system'}
		else:
			return {'status':False,'msg':result[1]}
	#def load_all_system_groups

	def load_admin_system_user(self):
		template = self.tpl_env.get_template('admin-users')
		if  objects.has_key("VariablesManager"):
			environment_vars = objects["VariablesManager"].get_variable_list(['LDAP_BASE_DN','SAMBASID'])
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
			string_template = template.render(environment_vars).encode('utf-8')
			aux_dic = ast.literal_eval(string_template)
			
			if not objects.has_key('SlapdManager'):
				return {'status':False,'msg':'This function depend on SlapdManager, but this is not installed or not working'}
			result = objects['SlapdManager'].insert_dictionary(aux_dic,i_existing=True)
			if not result['status']:
				return result
			aux_dn = aux_dic.keys()[0]
			result = self.insert_to_admin_profile(aux_dn,aux_dic[aux_dn]['uid'])
			if not result['status']:
				return result
		result = self.update_xid_counter("ou=Admins,ou=People,"+environment_vars['LDAP_BASE_DN'],max_uid)
		if result[0]:
			return {'status':True,'msg':'Load all admin users from system'}
		else:
			return {'status':False,'msg':result[1]}
	#def load_admin_system_user
	
	def load_net_admin_user(self,password=None):
		template = self.tpl_env.get_template('net-admin-user')
		if  objects.has_key("VariablesManager"):
			if not objects.has_key('SlapdManager'):
				return {'status':False,'msg':'This function depend on SlapdManager, but this is not installed or not working'}
			environment_vars = objects["VariablesManager"].get_variable_list(['LDAP_BASE_DN','SAMBASID'])
			environment_vars['USERPASSWORD'] = objects['SlapdManager'].generate_ssha_password(password).strip()
			environment_vars["NTPASSWORD"]=smbpasswd.nthash(password)
			environment_vars["LMPASSWORD"]=smbpasswd.lmhash(password)
			environment_vars["LASTSET"]=str(int(time.time()))
			string_template = template.render(environment_vars).encode('utf-8')
			aux_dic = ast.literal_eval(string_template)
			result = objects['SlapdManager'].insert_dictionary(aux_dic,i_existing=True)
			if not result['status']:
				return result
			aux_dn = aux_dic.keys()[0]
			result = self.insert_to_admin_profile(aux_dn,aux_dic[aux_dn]['uid'])
			if not result['status']:
				return result
			result = self.insert_to_admin_groups(aux_dic[aux_dn]['uid'])
			if not result['status']:
				return result
			result = self.update_xid_counter("ou=Admins,ou=People,"+environment_vars['LDAP_BASE_DN'],1042)
			if result[0]:
				return {'status':True,'msg':'Load all admin users from system'}
			else:
				return {'status':False,'msg':result[1]}
		else:
			return {'status':False,'msg':'Variables Manager n4d plugin not working'}
			
	def load_ro_admin_user(self):
		
		template=self.tpl_env.get_template("ro-admin-user")
		
		environment_vars=objects["VariablesManager"].get_variable_list(["LDAP_BASE_DN"])
		password="".join(random.sample(string.letters+string.digits, 4))
		environment_vars["PASSWORD"]=objects['SlapdManager'].generate_ssha_password(password).strip()
		string_template=template.render(environment_vars).encode("utf-8")
		aux_dic=ast.literal_eval(string_template)
		result=objects["SlapdManager"].insert_dictionary(aux_dic,i_existing=True)
		
		return result
		
		
	#def load_ro_admin_user
	
	def load_education(self):
		template = self.tpl_env.get_template('education')
		if  objects.has_key("VariablesManager"):
			environment_vars = objects["VariablesManager"].get_variable_list(['LDAP_BASE_DN','SAMBASID'])
		string_template = template.render(environment_vars).encode('utf-8')
		aux_dic = ast.literal_eval(string_template)
		if not objects.has_key('SlapdManager'):
			return {'status':False,'msg':'This function depend on SlapdManager, but this is not installed or not working'}
		result = objects['SlapdManager'].insert_dictionary(aux_dic,i_existing=True)
		if not result['status']:
			return result
		result = self.update_xid_counter("ou=Profiles,ou=Groups,"+environment_vars['LDAP_BASE_DN'],10005)
		if result[0]:
			objects['VariablesManager'].init_variable('ENABLE_NSS_LDAP',{'ENABLE_NSS_LDAP':'ENABLED'})
			return {'status':True,'msg':'Load structure for education model'}
		else:
			return {'status':False,'msg':result[1]}
	#def load_education
	
	def configure_smb(self):
		template = self.tpl_env.get_template('smb.conf')
		if  objects.has_key("VariablesManager"):
			objects['VariablesManager'].init_variable('DEADTIME')
			objects['VariablesManager'].init_variable('SAMBA_DOMAIN_NAME')
			objects['VariablesManager'].init_variable('NAME_SERVER_SAMBA')
			environment_vars = objects["VariablesManager"].get_variable_list(['SAMBA_DOMAIN_NAME','NAME_SERVER_SAMBA','DEADTIME','LDAP_BASE_DN'])
		string_template = template.render(environment_vars).encode('utf-8')
		tmp,filename=tempfile.mkstemp()
		f = open(filename,'w')
		f.writelines(string_template)
		f.close()
		n4d_mv(filename,'/etc/samba/smb.conf')
		return {'status':True,'msg':'Configured samba'}
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
		result = objects['SlapdManager'].load_acl()
		if not result['status']:
			return result
		return {'status':True,'msg':'Loaded acl'}
	#def load_acl_samba
	
	def update_root_password_samba(self,password):
		subprocess.Popen(['smbpasswd','-w',password],stdout=subprocess.PIPE).communicate()
		return {'status':True,'msg':'Update root password on samba database'}
	#def update_root_password_samba
	
	def insert_to_admin_profile(self,dn,uid):
		if not self.test_ldap_connection():
			if not self.connection_ldap():
				return {"status":False,"msg":"Connection with ldap is not created"}
		if  objects.has_key("VariablesManager"):
			environment_vars = objects["VariablesManager"].get_variable_list(['LDAP_BASE_DN'])
		path = "cn=admins,ou=Profiles,ou=Groups,"+  environment_vars['LDAP_BASE_DN']
		mod_list=[]
		mod=(ldap.MOD_ADD,"memberUid",str(uid))
		mod_list.append(mod)
		for x in mod_list:
			try:
				self.connect_ldap.modify_s(path,[x])
			except ldap.ALREADY_EXISTS as e:
				pass
			except Exception as e:
				return {'status':False,'msg':'insert_to_admin_profile error :'+ str(e)}
		return {'status':True,'msg':str(uid)+ 'has been added to admin profile'}
	#def insert_to_admin_profile
	
	def insert_to_admin_groups(self, uid):
		if not self.test_ldap_connection():
			if not self.connection_ldap():
				return {"status":False,"msg":"Connection with ldap is not created"}
		if  objects.has_key("VariablesManager"):
			environment_vars = objects["VariablesManager"].get_variable_list(['LDAP_BASE_DN'])
		system_admin_groups = ['sudo','adm','plugdev','lpadmin','cdrom','dip','epoptes']
		for group in system_admin_groups:
			mod=(ldap.MOD_ADD,"memberUid",str(uid))
			group_path="cn=" + group +",ou=System,ou=Groups," + environment_vars['LDAP_BASE_DN']
			try:
				self.connect_ldap.modify_s(group_path,[mod])
			except ldap.ALREADY_EXISTS as e:
				pass
			except Exception as e:
				return {'status':False,'msg':'insert to admin group error :'+ str(e)}	
		return {'status':True,'msg':'All ok'}

	def set_sambasid(self,sambasid):
		result = os.system('net setlocalsid ' + sambasid)
		if result == 0:
			return{'status':True,'msg': 'SID ' + str(sambasid) + ' has been set'}
		else:
			return{'status':False,'msg': 'SID could not change'}
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
			environment_vars = objects["VariablesManager"].get_variable_list(['LDAP_BASE_DN'])
			self.connect_ldap.bind_s("cn=admin,"+environment_vars['LDAP_BASE_DN'],password)
			return True
		except Exception as e:
			print "\n\nError" + str(e) + "\n\n"
			self.connect_ldap = None
			return False

	# def connection_ldap
