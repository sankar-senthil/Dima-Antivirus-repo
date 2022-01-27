""" 
    The Antivirus Software to detect and clean the infected files from your computer.
"""
__author__ = "sankarsenthil"
__maintainer__ = "sankarsenthil"
__copyright__ = "Copyright 2020, dimabusiness.com"
__status__ = "Production"

import sys
import os
import subprocess
import shutil
import sqlite3 as sq
import time
import sqlite3 
import json 
import platform

time.sleep(3)
App_Title = "UR_Pro_Handler"

Architecture = platform.architecture()[0]

Extension = '.exe' if 'exe' in sys.argv[0] else '.py'
DIR_PATH = sys.argv[0].replace('\\', '/').replace(f"{App_Title}{Extension}", "")

DB_FILE = f"{DIR_PATH}ANTIVIRUS.db"
DB_JSON_FILE = f"{DIR_PATH}dbtable_json_creater.json"
ARG_IN = sys.argv[-1]

Folder_Path = f"{DIR_PATH}Dima Antivirus/{Architecture}" if ARG_IN == "AV_Update" else f"{DIR_PATH}TempAV"
Temp_Path = f"{DIR_PATH}TempAV"

Folder_Path = f"{DIR_PATH}Dima Antivirus/{Architecture}"
ARG_IN = "AV_Update"
print(Folder_Path)

'' if os.path.exists(Temp_Path) else os.mkdir(Temp_Path)

UR_Process =  'U' if ARG_IN == "AV_Update" else 'R'
try:
    con = sq.connect(DB_FILE)
    cursur = con.cursor()
    cursur.execute("Update Auth set Update_Status  = 'S', UR_Process = '"+UR_Process+"'")
    con.commit()
    con.close() 
except Exception as exe:
    print(exe)
    
#### TRY: BLOCK FOR COPY,MOVE AND DELETE FILE FROM DOWNLOADED AND TEMP FOLDERS
try:
    if os.path.exists(Folder_Path):
        #### REMOVE OR COPY THE FILES FROM DIMAV FILE LOCATION
        for path_ in os.listdir(DIR_PATH):
            Main_Dir = f"{DIR_PATH}{path_}"            
            if os.path.samefile(Main_Dir, sys.argv[0]) or os.path.samefile(Main_Dir, Folder_Path):
                pass
            else:
                
                if ARG_IN == "AV_Update" and Main_Dir.split('/')[-1] not in ['Dima Antivirus','ANTIVIRUS.db'] and 'unins' not in Main_Dir.split('/')[-1] :   
                    try:shutil.move(Main_Dir, Temp_Path)
                    except Exception as exe:print(exe)
                else:
                    if ARG_IN != "AV_Update" and  Main_Dir.split('/')[-1] not in ['TempAV','ANTIVIRUS.db'] and 'unins' not in Main_Dir.split('/')[-1]:
                        try:os.remove(Main_Dir)
                        except:shutil.rmtree(Main_Dir)
                    else:
                        pass
                    
        #### MOVE THE FILE FROM DOWNLOAD OR TEMPAV PATH DEPENDS ON THE PROCESS                   
        for main_path in os.listdir(Folder_Path):
            Main_Dir = f"{Folder_Path}/{main_path}"
            try:
                shutil.copy(Main_Dir, DIR_PATH)
            except:
                try:
                    shutil.copytree(Main_Dir, f"{DIR_PATH}{main_path}")
                except:pass
                
        #### TO REMOVE FOLDER_PATH 
        try:shutil.rmtree(f"{DIR_PATH}Dima Antivirus")
        except Exception as exe:print('from',exe)
        
        #### CHECK AND ADD TABLES COLUMNS IN ANTIVIRUS.DB FILE
        try:
            con = sq.connect(DB_FILE)
            cursur = con.cursor()
            cursur.execute("Update Auth set Update_Status  = 'Y', last_Update = (SELECT strftime('%Y-%m-%d %H:%M:%S', datetime('now')))")
            con.commit()
        except Exception as exe:
            print(exe)
        finally:
            con.close() 
            
            
        try:
            DB_Table_structure = json.load(open(DB_JSON_FILE,'r'))
            con = sqlite3.connect( DB_FILE )
            cur = con.cursor()
            DBTab_names = cur.execute("SELECT name FROM  sqlite_master WHERE  type ='table' AND  name NOT LIKE 'sqlite_%';").fetchall()
            DBTab_names = [i[0] for i in DBTab_names]
            for table_name in DB_Table_structure['Table Names']:
                if table_name in DBTab_names:
                    pass 
                else:
                    cur.execute(DB_Table_structure["Create Table"][table_name])
                    con.commit()
                    
                cur.execute("SELECT * FROM "+table_name+" limit 1")
                col_name_list = [tuple[0] for tuple in cur.description]
                for column_name in DB_Table_structure[table_name]:
                    if column_name in col_name_list:
                        pass
                    else:
                        print(column_name)
                        cur.execute("ALTER TABLE "+table_name+" ADD "+column_name+" TEXT;")
                    con.commit()
                con.commit()
        except:
            pass
        
        #### TO START MAIN Dima Antivirus.EXE FILE
        try:subprocess.Popen(f"{DIR_PATH}Dima Antivirus.exe")
        except:os.startfile("Dima Antivirus.exe")

except Exception as exe:
    print(exe)
