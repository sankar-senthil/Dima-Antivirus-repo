""" 
    The Antivirus Software to detect and clean the infected files from your computer.
"""
__authors__ = "DIMA Production Team"
__copyright__ = "Copyright 2020, dimabusiness.com"
__version__ = "v2.3"
__maintainer__ = "DIMA Production Team"
__status__ = "Production"

import os, subprocess, sys,shutil
from pathlib import Path

hm_path = f"{Path.home()}/AppData/Local/Temp"

#### EXECUTABLE FILE NAME VARIABLE AND VALUE 
AV_TITLE = "Dima Antivirus"
AV_EXE_NAME = AV_TITLE+".exe"

#### GETTING TEMP PATH FOR CREATE AND REMOVE A ON_HIDE_OPENAV FILE
on_hide_filename = str(os.path.join(Path.home(), r"AppData\Local\Temp\{}_on_hide".format(AV_TITLE)))

### REMOVE A ON_HIDE_OPENAV FILE (HELPS TO SHOW THE HIDDEN WINDOW)
try:os.unlink(on_hide_filename)
except:pass

dir_path = sys.argv[0].replace('\\','/').replace('DimaAV_startup.exe','')
SCAN_WITH =  F"{dir_path}scan_with.txt"
    
try:
    ### CHECKS AND WRITE THE ARGUMENT PATH TO TEXT FILE 
    if sys.argv[1]:
        if sys.argv[-1] == 'from_startup':
            pass
        else:
            open(SCAN_WITH,'w').write(sys.argv[1])
    else: pass
except:
        pass


import psutil
### CHECKS IF THE PROCESS ALREADY RUNS OR NOT IF RUNS RETURN LENGTH OF THE PROCESS
AV_process_status = len([p.name() for p in psutil.process_iter() if p.name() == AV_EXE_NAME])

if AV_process_status:
    pass
else:
    if sys.argv[-1] == "from_startup":
        subprocess.Popen([f"{dir_path}{AV_EXE_NAME}",sys.argv[1]])
    else:
        subprocess.Popen(f"{dir_path}{AV_EXE_NAME}")


for _path in os.listdir(hm_path):
    act_path = os.path.join(hm_path,_path)
    try:
        os.remove(act_path)
    except:
        try:
            shutil.rmtree(act_path)
        except:pass
    
    

        
