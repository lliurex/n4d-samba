from StringIO import StringIO
from ConfigParser import SafeConfigParser

data = StringIO('\n'.join(line.strip() for line in open('/etc/samba/smb.conf')))
print (data)
parser = SafeConfigParser()
parser.readfp(data)

