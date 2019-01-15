#!/bin/bash
LDAP=$(ldapsearch -x | grep sambaSID | cut -d " " -f2 | cut -d "-" -f -7 | sort -u)
LOCALSAMBA=$(net getlocalsid 2> /dev/null)
DOMAINSAMBA=$(net getdomainsid 2> /dev/null)
FICHERO=$(mktemp).txt

echo -e "\n\n\n" 
echo -e "\n========= Resultados de LDAP ========= \n"
for x in $LDAP; do 
	echo $x
done
echo -e "\n========= Resultados de LOCAL ========= \n"$LOCALSAMBA
echo -e "\n========= Resultados de Dominio ========= \n"$DOMAINSAMBA

rm $FICHERO
touch $FICHERO
echo -e "\n========= Resultados de LDAP ========= \n" >> $FICHERO
for x in $LDAP; do 
	echo $x >> $FICHERO
done

echo -e "\n========= Resultados de LOCAL ========= \n"$LOCALSAMBA >> $FICHERO
echo -e "\n========= Resultados de Dominio ========= \n"$DOMAINSAMBA >> $FICHERO

echo -e "\n\n\nPodeis enviar el fichero $FICHERO al foro de LlliureX\n\n\n" 
