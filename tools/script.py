#!/usr/bin/env python3

from jinja2 import Environment, meta
from jinja2.loaders import FileSystemLoader

env = Environment(loader=FileSystemLoader('install/usr/share/n4d/templates/samba'))
source_template = env.loader.get_source(env,'basic-structure')
parsed_template = env.parse(source_template)
print (meta.find_undeclared_variables(parsed_template))
