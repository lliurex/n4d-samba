import ldap
import ldap.sasl

auth=ldap.sasl.sasl('','EXTERNAL')
l=ldap.initialize('ldapi:///',trace_level=0)

l.protocol_version=3

try:
	
	l.sasl_interactive_bind_s("",auth)
	
	
	l.search_s('dc=lliurex',ldap.SCOPE_SUBTREE)
	print (l.search_s('cn=config',ldap.SCOPE_SUBTREE,'cn=*',['cn']))
	
	
except Exception as e:
	print ("!")
	print (e)
