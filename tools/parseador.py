#!/usr/bin/env python3
import json
import ldap
import ldap.modlist
f = open("grupossamba",'r')
total = f.readlines()
objeto = {}
listado = {}
for linea in total:
    if linea != '\n':
        x,y = linea[:len(linea) - 1 ].split(':')
        if 'dn' in x:
            print (y)
        if objeto.has_key(x):
            if type(objeto[x]) == type(""):
                aux = objeto[x]
                objeto[x] = [aux,y.strip()]
            elif type(objeto[x]) == type([]):
                objeto[x].append(y.strip())
        else:
            objeto[x] = y.strip()
    else:
        dn = objeto.pop('dn')
        print (dn)
        listado[dn]= objeto
        #listado[dn] = ldap.modlist.addModlist(objeto)
        #print ldap.modlist.addModlist(objeto)
        objeto={}
if objeto != {}:
    dn = objeto.pop('dn')
    listado[dn]= objeto
    #listado[dn] = ldap.modlist.addModlist(objeto)
    #print ldap.modlist.addModlist(objeto)
    objeto={}

for w in listado.keys():
    print (w)
print (json.dumps(listado,indent=8))
