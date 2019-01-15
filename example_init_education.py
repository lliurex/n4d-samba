#!/usr/bin/python
import xmlrpclib

ip_server = '10.0.0.246'
c = xmlrpclib.ServerProxy("https://"+ip_server+":9779")
#c = xmlrpclib.ServerProxy("https://192.168.1.2:9779")
user = ("lliurex","lliurex")

#print c.get_methods('SambaManager')

#restore : adm admins
#print c.load_schema(user,'SambaManager')
#print c.load_index(user,'SambaManager')
#print c.load_basic_structure(user,'SambaManager')
#print c.load_all_system_groups(user,'SambaManager')
print c.load_net_admin_user(user,'SambaManager','lliurex')
#print c.load_admin_system_user(user,'SambaManager')
#print c.load_education(user,'SambaManager')
#print c.configure_smb(user,'SambaManager')
#print c.load_acl_samba_education(user,'SambaManager')
#print c.update_root_password_samba(user,'SambaManager','lliurex')
#test : * anonymous 
#backup : adm admins
