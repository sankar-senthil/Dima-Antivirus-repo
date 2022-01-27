
""" 
    The Antivirus Software to detect and clean the infected files from your computer.
"""
__authors__ = "DIMA Production Team"
__copyright__ = "Copyright 2020, dimabusiness.com"
__version__ = "v2.3"
__maintainer__ = "DIMA Production Team"
__status__ = "Production"


import time
import stat
import hashlib
import os
import win32api
import gc
import psutil
import zipfile
import subprocess
import logging
from pathlib import Path
from threading import Thread
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
from logging.handlers import RotatingFileHandler
from Empx.utils import AntivirusUtility as AS, ApiLinks, GeneralMethods as GM

dir_path = GM.dir_path

Antutl_instance = AS()

DB_NAME = f"{dir_path }ANTIVIRUS.db"
AV_ACTION = dir_path+'AV_ACTION.json'
log_file = dir_path+"AV_LEDGER.log"
log_mode = "a" if os.path.exists(log_file) else "w"
logging.basicConfig(
    handlers=[RotatingFileHandler(
        filename=log_file, mode=log_mode, maxBytes=50000000, backupCount=10)],
    level=logging.INFO, format="%(asctime)s:%(message)s", datefmt='%Y-%m-%d %H:%M:%S'
)

threat_action = dir_path+'threat_action.txt'

global monitoring_interupt
monitoring_interupt=False

AV_TITLE = "Dima Antivirus"
AV_EXE_NAME = AV_TITLE+".exe"

class Handler(PatternMatchingEventHandler):
    def __init__(self):
        self.ignorePatterns = [
                "*.tmp","*.TMP","*.tmp.","*.TMP.",
                "*.log","*.log.","*.LOG","*.LOG1","*.LOG2","*.dat.LOG2",
                "*-journal","*journal.",
                "*.pf","*.ttf","*.pak",
                "*.py","*.pyc","*.c","*.java","*.php","*.vb","*.cs","*.cpp","*.class","*.cgi","*.pl","*.h" ## common programming Languages
                "*.bak", "*.cab", "*.cfg", "*.cpl", "*.cur", "*.dll","*.dmp","*.drv","*.icns","*.ico", "*.ini",
                "*.lnk", "*.msi", "*.sys", "*.tmp",
                ]
        self.ignoreDirectories = True
        PatternMatchingEventHandler.__init__(self, ignore_patterns= self.ignorePatterns, ignore_directories=self.ignoreDirectories, case_sensitive=False)

    def on_any_event(self,event):
        """ 
        The function is to helps if any modifications happens in the system either create, download, delete or modification
        it will get the file name and sent to the scanner
        """
        try:
            if event.is_directory:
                return None
            if event.event_type == 'created'or event.event_type ==  'modified'or event.event_type ==  'moved':
                
                srcPath = r"{}".format(event.src_path)
                if os.path.isfile(srcPath):
                    if 'Dima_Vault' in srcPath:
                        return
                    else:
                        try:
                            file_size = os.path.getsize(srcPath)/1024000

                            if file_size >= 25:
                                pass
                            else:
                                ignore_ls = [i for i in GM.AV_WIDGETS_ACTION['ignoreList'] if i in srcPath]
                                
                                if ignore_ls : 
                                    pass
                                else:
                                    ignore_pt = [i for i in GM.AV_WIDGETS_ACTION['ignorePatterns'] if os.path.splitext(srcPath)[-1] in i and os.path.splitext(srcPath)[-1] != '']
                                    if ignore_pt:
                                        pass
                                    else:
                                        AntivirusBackend().antivirus_scanner(srcPath)
                        except:
                            pass
                        return
            else:
                return None
        except:
            logging.exception(f"ERROR-MESSAGE")

class AntivirusBackend():
    """ 
    AntivirusBackend Class handles the Backend Operation such as Real Time Protection( Monitoring ) and Scanner Method
    This function has following Methods (__init__, monitoring_interupt_fun, usbScan, antivirus_monitor, query_updation, 
    access_checkand_Encryption, antivirus_scanner)
    """
    AV_WIDGETS_ACTION = ''
    def __init__(self):
        self.monitoring_interupt = ''
        self.user_action_feed, self.offline_master_feed = '', ''
        self.isMalicious, self.threatName, self.access_denied = 0, None, False
    
    def monitoring_interupt_fun(self, interrupt):
        """
        monitoring_interupt_fun Method is helps to terminate the Monitoring process
        """
        global monitoring_interupt
        if interrupt=='on':
            monitoring_interupt = False        
        elif interrupt=='off':
            monitoring_interupt = True
        else:
            pass
        return monitoring_interupt

    def usbScan(self,drive_):
        """ usbScan Mehtod starts scanning if usb inject or already in connection
        """
        logging.info(f"usbScan method call received.. {drive_}")
        try:
            for path, subdirs, files in os.walk(drive_):           
                if monitoring_interupt:
                    break
                else:pass
                for name in files:
                    if monitoring_interupt:
                        break
                    else:pass
                    
                    file_source_path = os.path.join(path, name)
                    srcPath = r"{}".format(file_source_path)
                    if os.path.isfile(srcPath):
                        try:
                            if 'Dima_Vault' in srcPath:
                                pass
                            else:
                                try:
                                    file_size = os.path.getsize(srcPath)/1024000

                                    if file_size >= 25:
                                        pass
                                    else:
                                        ignore_ls = [i for i in GM.AV_WIDGETS_ACTION['ignoreList'] if i in srcPath]
                                
                                        if ignore_ls : 
                                            pass
                                        else:
                                            ignore_pt = [i for i in GM.AV_WIDGETS_ACTION['ignorePatterns'] if os.path.splitext(srcPath)[-1] in i and os.path.splitext(srcPath)[-1] != '']
                                            if ignore_pt:
                                                pass
                                            else:
                                                AntivirusBackend().antivirus_scanner(srcPath)
                                except:pass
                                
                        except Exception as exception:
                            print('usbScan-->',exception)
                    else:
                        pass
            return "completed"
        except:
            logging.exception(f"ERROR-MESSAGE")
            return "completed"

    def av_watchdog(self,LOC = 'Other'):
        try:
            global monitoring_interupt
            event_handler = Handler()
            observer = Observer()
            drives = win32api.GetLogicalDriveStrings()
            drives = drives.split('\000')[:-1]

            if LOC == "Downloads":
                observer.schedule(event_handler, path = f"{Path.home()}\\Downloads", recursive=True)
            else:
                for p_ in drives:
                    observer.schedule(event_handler, path = p_, recursive=True)
            observer.start()

            while True:
                    #### THE BELOW IF STATEMENT FOR INTERRUPT THE MONITORING
                    if monitoring_interupt:
                        AS.show_notification(f"{AV_TITLE} Monitoring Process Stopped !!!")
                        observer.stop()
                        break
                    else:pass
                    time.sleep(0.5)

        except Exception as e:
            print('av_watchdog',e)
            observer.stop()
        finally:
            observer.join()
        
    def antivirus_monitor(self):
        """
        antivirus_monitor Method is helps to run monitoring options like observer and start while loop to check continuesly 
        it checks the files are malicious or not whil real time protection is on
        """        
        
        try:
            prevLength, currentLength = 0, 0
            new_dev, processed_dev = [], []

            while True:
                #### THE BELOW IF STATEMENT FOR INTERRUPT THE MONITORING
                if monitoring_interupt:
                    break
                else:pass
                time.sleep(1)
                ## USB MONITOR -- started ---
                current_devices = AS.get_removable_devices()
                if current_devices:
                    currentLength = len(current_devices)
                else:
                    new_dev.clear()
                    processed_dev.clear()
                    currentLength = 0

                if currentLength != prevLength:
                    for dev in current_devices:
                        if dev not in new_dev and dev not in processed_dev:
                            new_dev.append(dev)
                        if new_dev:
                            for scan_ in new_dev:
                                logging.info(f"NEW External Device Found : {scan_}")
                                scan_status = self.usbScan(scan_)
                                if scan_status == "completed" or scan_status == "ejected":
                                    processed_dev.append(scan_)
                                    new_dev.remove(scan_)
                                    break
                        else:
                            pass
                else:
                    pass

        except KeyboardInterrupt:
            pass

    def query_updation(self,current_datetime,MD5_HASH,srcPath,file_name):
        
        AS.db_management(

                                        """
                                        INSERT INTO user_action(date_time,file_name,source_path,hash_id)
                                        SELECT '"""+current_datetime+"""','"""+file_name+"""','"""+srcPath+"""',id
                                        FROM   offline_master WHERE  MD5_HASH = '"""+MD5_HASH+"""' 
                                        """
                                        )
        return
    
    
    def access_checkand_Encryption(self,srcPath):
        """
        This Method is used to find and quarantine the malicious files
        """
        exceptThreats = ['Open']
        #### FILE CURRENT PERMISSION
        mask = stat.S_IMODE(os.lstat(srcPath).st_mode)

        if not self.access_denied:
            if self.isMalicious == True and self.threatName != None and self.threatName.find(exceptThreats[0]) == -1:
                try:
                    if os.path.isfile(srcPath) == True:
                        # if THREAT_ACTION_MODE == "Quarantine":
                        """ As per client request we are not going to Eject. We will encrypt that file on same location. """
                        Antutl_instance.antivirus_encryptor(srcPath)
                        AS.show_notification(f"VIRUS - {self.threatName} Found.\nIt's Quarantined Successfully.")

                except Exception as exception:
                    print('access_checkand_Encryption--->',exception)
                            
                    if os.path.isfile(srcPath) == True:

                        try:
                            os.chmod(srcPath, mask)
                            # if THREAT_ACTION_MODE == "Quarantine":
                            """ As per client request we are not going to Eject. We will encrypt that file on same location. """
                            Antutl_instance.antivirus_encryptor(srcPath)
                            AS.show_notification(f"VIRUS - {self.threatName} Found.\nIt's Quarantined Successfully.")
                            
                        except Exception as exception:
                            print('access_checkand_Encryption--->',exception)
                            
            else:
                if self.threatName and os.path.isfile(srcPath) == True:
                    if self.threatName.find(exceptThreats[0]) != -1:
                        pass 
                else:
                    pass
                
                ### File restored with previous permission.
                try:
                    if os.path.isfile(srcPath) == True:
                        try:
                            os.chmod(srcPath, mask)
                        except Exception as exception:
                            print('access_checkand_Encryption--->',exception)
                            
                except PermissionError:
                    pass 
                    
    def malware_zip_handler(self,srcPath):
        try:
            unzipped_file = zipfile.ZipFile(srcPath, "r")
            for i in unzipped_file.namelist():
                if GM.scan_status:
                    return 0
                else :
                    pass
                binary_data = unzipped_file.open(i,'r').read()
                MD5_HASH = hashlib.md5(binary_data).hexdigest()
                SHA256_HASH = hashlib.sha256(binary_data).hexdigest()


                User_Action_Data = AS.db_management("""
                                                                        SELECT a.date_time,source_path,a.id hash_id,action,malicious,threat_name,Ignore_Action
                                                                        FROM  (SELECT * FROM   offline_master WHERE  MD5_HASH = '"""+MD5_HASH+"""' and SHA256_HASH = '"""+SHA256_HASH+"""')a
                                                                        LEFT JOIN (SELECT * FROM   user_action WHERE  source_path = '"""+srcPath+"""')b
                                                                        ON a.id = b.hash_id 
                                                                        """
                                                                        )
                    
                if User_Action_Data:
                    Date, source_path, hash_id, Action,self.isMalicious  ,self.threatName, self.ignore_data = User_Action_Data[-1]
                    self.isMalicious = True if self.isMalicious else False
                    if self.isMalicious:
                            return 1
                else:
                    if AS.check_Internet_req():
                        print("AntiVirus_res")
                        AntiVirus_res = GM.api_request( ApiLinks.ANT_HASH % (MD5_HASH, SHA256_HASH, GM.license_key, GM.MAC_Address))
                        print("AntiVirus_res",AntiVirus_res)
                        if GM.scan_status:
                            return 0
                        else :
                            pass
                        if AntiVirus_res['status_code'] != 200 :
                            # GM.Auth_table_dict['remaining_days'] = 'Duplicate'
                            self.threatName,self.isMalicious
                        else:
                            self.isMalicious = AntiVirus_res['response_json']['isMalicious']
                            self.threatName = AntiVirus_res['response_json']['Threat']

                            if self.isMalicious:
                                return 1
                            else:return 0
                    else :return 0
        except:
            return 0

    def antivirus_scanner(self,srcPath,is_usb=False):
        """ 
        This is the main function for scanning it collects the hash value from the file path and if it is in local(database) to go with other process
        if not it call the api link and feed in to database if it is malicious it calls the required function to remove the source fie and quarantine to dima_vault
        """
        time.sleep(0.5)

        if os.path.splitext(srcPath)[-1] == '.lnk' and is_usb:
            src_path = srcPath.replace('\\','/')
            src_path = src_path.replace(src_path.split('/')[-1],'')
            subprocess.run([f"attrib –h –r –s {src_path} /s /d"], shell=True)
            print('src_path',src_path)
        else:
            pass

        if os.path.exists(srcPath):
            srcPath = r"{}".format(srcPath).replace("\\","/")
            path_split = srcPath.split('/')
            file_name = path_split[-1]
            current_datetime = str(datetime.now())  
            self.isMalicious, self.threatName, self.ignore_data = False, None, None

            if os.path.exists(srcPath) and os.path.isfile(srcPath):
                self.access_denied = False

                file_size = os.path.getsize(srcPath)/1024000
                
                # if file_size >= 25:
                #     return tuple((False, None ))
                # else:
                # #     ignore_ls = [i for i in GM.AV_WIDGETS_ACTION['ignoreList'] if i in srcPath]
                # #     ignore_pt = [i for i in GM.AV_WIDGETS_ACTION['ignorePatterns'] if os.path.splitext(srcPath)[-1] in i and os.path.splitext(srcPath)[-1] != '']
                
                # # if ignore_ls or ignore_pt : 
                # #     return tuple((False, None ))
                    
                # # else:
                mask = stat.S_IMODE(os.lstat(srcPath).st_mode)
                os.chmod(srcPath, mask)
                os.chmod(srcPath, stat.S_IRWXU) 

                MD5_HASH = hashlib.md5(open(srcPath, 'rb').read()).hexdigest()
                SHA256_HASH = hashlib.sha256(open(srcPath, 'rb').read()).hexdigest()

                try:
                    User_Action_Data = AS.db_management("""
                                                                        SELECT a.date_time,source_path,a.id hash_id,action,malicious,threat_name,Ignore_Action
                                                                        FROM  (SELECT * FROM   offline_master WHERE  MD5_HASH = '"""+MD5_HASH+"""' and SHA256_HASH = '"""+SHA256_HASH+"""')a
                                                                        LEFT JOIN (SELECT * FROM   user_action WHERE  source_path = '"""+srcPath+"""')b
                                                                        ON a.id = b.hash_id 
                                                                        """
                                                                        )
                    
                    if User_Action_Data:
                        st_time = datetime.now()
                        Date, source_path, hash_id, Action,self.isMalicious  ,self.threatName, self.ignore_data = User_Action_Data[-1]
                        self.isMalicious = True if self.isMalicious else False

                        if hash_id and source_path:
                            self.offline_master_feed = False
                            if Action:         
                                if Action == 'Restore':
                                    self.isMalicious, self.threatName = 0, None
                                elif Action == 'Delete':
                                    self.access_checkand_Encryption(srcPath)
                                    AS.db_management("""
                                                                    update user_action set date_time = '"""+str(datetime.now())+"""', Action = NULL where source_path = '"""+srcPath+"""'
                                                                    """
                                                                    )
                                else:
                                    self.isMalicious, self.threatName= False, None 
                            else:
                                self.access_checkand_Encryption(srcPath) 
                                    
                        elif hash_id and not source_path and not self.ignore_data:
                            self.access_checkand_Encryption(srcPath)
                            self.query_updation(str(datetime.now()),MD5_HASH,srcPath,file_name)
                
                        else:   
                            self.isMalicious, self.threatName= False, None 

                    elif os.path.splitext(srcPath)[-1] in ['.zip']:
                        st_time = datetime.now()
                        res = self.malware_zip_handler(srcPath)
                        print(res)
                        print("GM.scan_status",GM.scan_status)
                        
                        if GM.scan_status:
                            return tuple((self.threatName,self.isMalicious))
                        else :
                            pass

                        if res:
                            self.access_checkand_Encryption(srcPath)
                            AS.db_management("insert into Offline_Master (Date_Time, MD5_HASH, Malicious, Threat_Name, SHA256_HASH)values(?,?,?,?,?)",tuple((current_datetime, MD5_HASH, self.isMalicious, self.threatName,   SHA256_HASH)))
                            self.query_updation(current_datetime,MD5_HASH,srcPath,file_name) if MD5_HASH else ''
                            return tuple((self.threatName,self.isMalicious))

                        else:
                            return tuple((self.threatName,self.isMalicious))
                                
                    else:
                        st_time = datetime.now()
                        if AS.check_Internet_req():
                            self.threatName,self.isMalicious = None, None
                            try:
                                
                                if type(GM.Auth_table_dict['remaining_days']) == int:
                                    AntiVirus_res = GM.api_request( ApiLinks.ANT_HASH % (MD5_HASH, SHA256_HASH, GM.license_key, GM.MAC_Address) )
                                    if AntiVirus_res['status_code'] != 200 :
                                        # GM.Auth_table_dict['remaining_days'] = 'Duplicate'
                                        return tuple((self.threatName,self.isMalicious))
                                    else:
                                        self.isMalicious = AntiVirus_res['response_json']['isMalicious']
                                        self.threatName = AntiVirus_res['response_json']['Threat']
                                        
                                else:
                                    AntiVirus_res = GM.api_request( ApiLinks.EMP_HASH % (MD5_HASH, SHA256_HASH) )
                                    if AntiVirus_res['status_code'] != 200 :
                                        # GM.Auth_table_dict['remaining_days'] = 'Duplicate'
                                        return tuple((self.threatName,self.isMalicious))
                                    else:
                                        self.isMalicious = AntiVirus_res['response_json']['isMalicious']
                                        self.threatName = AntiVirus_res['response_json']['Threat']
        
                            except Exception as exception:
                                print('hashApi-->',exception)
                                return tuple((self.threatName,self.isMalicious))
                            
                            if is_usb:
                                return [self.isMalicious,self.threatName]
                            else:pass
                            
                            self.access_checkand_Encryption(srcPath)
                            AS.db_management("insert into Offline_Master (Date_Time, MD5_HASH, Malicious, Threat_Name, SHA256_HASH)values(?,?,?,?,?)",tuple((current_datetime, MD5_HASH, self.isMalicious, self.threatName,   SHA256_HASH)))
                            self.query_updation(current_datetime,MD5_HASH,srcPath,file_name) if MD5_HASH else ''
                        else:
                            pass
                        
                    return tuple((self.threatName,self.isMalicious))

                except PermissionError:
                    self.access_denied = True

                finally:
                    GM.est_tm_calc = datetime.now() - st_time
        else:pass
        return
