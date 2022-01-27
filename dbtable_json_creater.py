""" 
    The Antivirus Software to detect and clean the infected files from your computer.
"""
__authors__ = "DIMA Production Team"
__copyright__ = "Copyright 2020, dimabusiness.com"
__version__ = "v2.1"
__maintainer__ = "DIMA Production Team"
__status__ = "Production"

import sqlite3 
import json
import sys
import os
import shutil, time

App_Title = 'dbtable_json_creater'
Extension = '.exe' if 'exe' in sys.argv[0] else '.py'
DIR_PATH = sys.argv[0].replace('\\', '/').replace(f"{App_Title}{Extension}", "")

destination = DIR_PATH.replace('PROGRAMMING_CODES/','EXE_JSON_FR_SPEC/')
src_file = f'{DIR_PATH}dbtable_json_creater.json'

con = sqlite3.connect( f"{DIR_PATH}ANTIVIRUS.db" )
cur = con.cursor()
Table_names = cur.execute("SELECT name FROM  sqlite_master WHERE  type ='table' AND  name NOT LIKE 'sqlite_%';").fetchall()
dbtable_json_creater = {'Table Names':[],"Create Table":{}}
for i in Table_names:
    dbtable_json_creater['Table Names'].append(i[0])
    create_table = cur.execute("SELECT sql FROM sqlite_master WHERE tbl_name = '"+i[0]+"';").fetchall()
    dbtable_json_creater['Create Table'][i[0]] = create_table[0][0]
    cur.execute(f"SELECT * FROM {i[0]} limit 1").fetchall()
    col_name_list = [tuple[0] for tuple in cur.description]
    dbtable_json_creater[i[0]] = col_name_list
with open(src_file,'w+') as file:
    json.dump(dbtable_json_creater,file,indent=4)
    
for i in os.listdir(destination):
    
    if i == 'dbtable_json_creater.json':
        try:
            os.remove(f"{destination}{i}")
        except:pass
    else:
        pass
try:
    shutil.move(src_file, destination)
    pass
except:pass