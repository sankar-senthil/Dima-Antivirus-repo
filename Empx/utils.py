""" 
    The Antivirus Software to detect and clean the infected files from your computer.
"""
__authors__ = "DIMA Production Team"
__copyright__ = "Copyright 2020, dimabusiness.com"
__version__ = "v2.3"
__maintainer__ = "DIMA Production Team"
__status__ = "Production"

import os
import gc
import re
import uuid
import stat
import socket
import psutil
import random
import base64
import logging
import requests
import win32file
import pyzipper
import platform
import sqlite3 as sq
from os.path import basename
from datetime import datetime, timedelta
from win10toast import ToastNotifier
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone, timedelta


Version = __version__.upper()
toast = ToastNotifier()
AV_TITLE = "Dima Antivirus"
AV_EXE_NAME = AV_TITLE+".exe"

class ApiLinks():
    """ This class has all api links """
    # MAIN_DOMAIN = 'http://10.10.10.121:5000/'
    # MAIN_DOMAIN = "https://emperor2.dimabusiness.com/"

    MAIN_DOMAIN = "https://antivirus1.dimabusiness.com"
    GET_LIC = f"{MAIN_DOMAIN}/api/get_license_key/?serial_number=%s"
    LIC_VERIFY = f"{MAIN_DOMAIN}/api/verify/?api_key=%s&mac=%s&otp=%s"
    EMP_HASH = f"{MAIN_DOMAIN}/av/hash?md5_hash=%s&sha256_hash=%s"
    PROD_INFO = f"{MAIN_DOMAIN}/api/productinfo/?api_key=%s&platform=%s&mac=%s&app_version=%s"

    ANT_HASH = f"{MAIN_DOMAIN}/api/antivirus/hash/?md5_hash=%s&sha256_hash=%s&api_key=%s&mac=%s"
    PRO_UPD_CHECK = f"{MAIN_DOMAIN}/version_check?api_key=%s&platform=%s&mac=%s&app_version=%s"
    DOWN_LAT_VER = f"{MAIN_DOMAIN}/download/antivirus/?platform=%s&version=%s"

class GeneralMethods():
    """
    GeneralMethods is a class from utils module it has following Methods ( __init__, initial_loads, delete_30dayrecord, auth_table_config,
    time_string_calculator, close_popup, machine_attributes, license_exp_date, api_request, otp_generator, send_otp, verify_otp, licence_popup_func, 
    software_update, path_spliter)
    
    """
    gc.collect()
    ####  CLASS VARIABLES
    lickey_status, popup_object_data, tooltip_object_data = "", "", []
    license_key, Product_information, licence_interrupt, ready_to_install = "", "", False, False
    Auth_table_dict, Auth_Fields, dir_path, ENCRYPTION_PATH = {}, [], '', ''
    Update_verche_json, Update_Status, tooltip_status = '', False, False
    MAC_Address, Machine_Name, Host_Name, Oper_System, Licence_check = '', '', '', '', False
    update_label_status, OTP_VALUE, Lic_tuple, remaining_days = False, '', '', 'Empty'
    Path_List, AV_WIDGETS_ACTION, scan_status, proxy_on = {}, '', False,0
    usr_email,email_count, serial_key, secret_password, est_tm_calc, file_cnt = '',1,'', b'L}_hdAVF?)X?AIHb#n', 1, 0
    
    

    def __init__(self):
        gc.collect()
        self.scan_file_list = []
        self.delete_30dayrecord()

    @classmethod
    def initial_loads(cls):
        
        """ The method calculates the latest version of the software """
        
        ### FUNCTION FOR CALCULATING THE LATEST VERSION
        def version_finder(attribute):
            if attribute.count('.') >= 2:
                attribute = attribute.rsplit(".", 1)
                attribute = float(''.join(i for i in attribute))
            else:
                attribute = float(attribute.split('V')[-1])
            return attribute
            
        if type(cls.Auth_table_dict['remaining_days']) == int:
            try:
                cls.license_exp_date()
                Product_information = cls.api_request(ApiLinks.PROD_INFO % (cls.Auth_table_dict['license'], cls.MAC_Address, platform.platform(), Version))
                cls.Update_verche_json = cls.api_request(ApiLinks.PRO_UPD_CHECK % (cls.Auth_table_dict['license'],platform.platform(),cls.MAC_Address,Version))['response_json']
            
                if cls.Update_verche_json and not cls.ready_to_install: 
                    src_app_version = cls.Update_verche_json['src_app_version'].split('V')[-1]
                    latest_version = cls.Update_verche_json['latest_version'].split('V')[-1]
                    src_app_version =  version_finder(src_app_version)
                    latest_version =  version_finder(latest_version)
                    
                    if latest_version > src_app_version:
                        cls.Update_Status = True
                    else:
                        cls.Update_Status = False
                else:
                    cls.Update_Status = False
                    
            except Exception as exe:
                print('initial_loads-->',exe)
                
    def delete_30dayrecord(self):
        """ This method is deletes 30 days before data in user action table ( database )"""
        
        for filename in os.listdir(self.ENCRYPTION_PATH):
            file_path = f"{self.ENCRYPTION_PATH}/{filename}"
            info = os.stat(file_path)
            modified_date = datetime.fromtimestamp(info.st_mtime, tz=timezone.utc).date()
            days30_fromnow = datetime.now().date()-timedelta(30)
            if modified_date <= days30_fromnow:
                try:
                    os.remove(file_path)
                    AntivirusUtility.db_management("""
                    DELETE FROM User_Action WHERE REPLACE(Date_Time, '/', '-') < date('now', '-30 day') AND Action is NULL or Action = 'DELETE'
                    """)
                except Exception as exe:
                    print('delete_30dayrecord--------->',exe)
                    pass
            else:
                pass
       
        return

    @classmethod
    def auth_table_config(cls):
        """ auth_table_config is a value maintainer for auth it collects the data from auth table and feed into dictionary """
        
        Auth_count = 0
        cls.Auth_table_dict = {}
        try:
            Auth_data = AntivirusUtility.db_management("select * from Auth")
            for i in cls.Auth_Fields:
                if Auth_data:
                    if not Auth_data[-1][Auth_count]:
                        if i == 'remaining_days':
                            cls.Auth_table_dict[i] = Auth_data[0][7]
                        elif i == 'license':
                            cls.Auth_table_dict[i] = Auth_data[0][4]
                        else:
                            cls.Auth_table_dict[i] = 0
                    else:
                        cls.Auth_table_dict[i] = Auth_data[-1][Auth_count]
                else:
                    if i == 'remaining_days':
                        cls.Auth_table_dict[i] = cls.remaining_days
                    elif i == 'license':
                        cls.Auth_table_dict[i] = cls.license_key
                    else:
                        cls.Auth_table_dict[i] = 0
                Auth_count+=1
        except Exception as exc:
            print('auth_table_config--->',exc)

        return cls.Auth_table_dict
    
        
    #### THE BELOW METHOD IS TO CALCULATE THE TIME WITH STRING EXTENSION FOR SCANNING
    def time_string_calculator(self,lastscan_time):
        try:

            lastscan_time = [i.split('.')[0] if '.' in i else i for i in lastscan_time ]    
            """ This Method is to calculate time format for full scan and custom scan """
            if lastscan_time[0] != '0' and lastscan_time[0] != '00':
                lastscan_time = lastscan_time[0].split(',')[0] if 'day' in lastscan_time[0] else f"{lastscan_time[0]} Hrs"

            elif lastscan_time[1] != '0' and lastscan_time[1] != '00':
                lastscan_time = f"{lastscan_time[1]} Min"

            elif lastscan_time[-1] != '0' and lastscan_time[-1] != '00':
                lastscan_time = f"{lastscan_time[-1]} Sec"

            else:
                lastscan_time = '00 Sec'
            return lastscan_time
        except:
            return '00 Sec'


    #### THE CLASS METHOD IS USED TO KILL AND REFRESH THE ACTION POPUP
    @classmethod
    def close_popup(cls,object_data='',pro = ''):
        """ This function is to store the object data from popup and close """
        if pro == 'tooltip':
            cls.tooltip_object_data.append(object_data)
        else:
            cls.popup_object_data = object_data

    @classmethod
    def machine_attributes(cls):
        """ This Method it to find system attributes"""
        cls.MAC_Address = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
        cls.Machine_Name = platform.node()
        cls.Host_Name = socket.gethostname()
        cls.Oper_System = platform.platform()
        return 

    #### THE BELOW METHOD IS TO CHECK AND UPDATE LICENSE DATE 
    @classmethod
    def license_exp_date(cls):
        """ This function is helps to calculate the license expire when the system is in offline """
        currentdate = datetime.now().date()
        AntivirusUtility.db_management(
            """
            update Auth set Remaining_Days = (select case when date<0 then 'Expired' else date end date from (select JULIANDAY(Expiry_Date) - JULIANDAY('"""+str(currentdate)+"""') date from Auth)a),Last_Verified = '"""+str(currentdate)+"""'
            where not exists (select last_verified from auth where last_verified like '"""+str(currentdate)+"""%')
            """     
            )
        
        AntivirusUtility.db_management("update auth set current_version = '"+Version+"' where current_version <> '"+Version+"'")
        # Lic_API_Data = cls.api_request(ApiLinks.LIC_VERIFY % (cls.MAC_Address, cls.Auth_table_dict['license']))

    @classmethod
    def api_request(cls, url):
        """ The method is helps to send and receive API requests  """
        API_dict = {}
        print(url)
        try:
            data = {}
            headers = {}           
            response = requests.request("POST", url, headers=headers, data=data)
            # print(response.json())
            API_dict['status_code'] = response.status_code
            if response.status_code in [200, 201, 208, 400]:
                API_dict['response_json'] = response.json()
            # elif response.status_code == 400:
            #     API_dict['msg'] = response.json()
            return API_dict
            
        except Exception as exe:
            print('api_request--->',exe)
            return API_dict 

        finally:
            response.close()
        
    @classmethod
    def otp_generator(cls):
        """ The Method is helps to generate OTP """
        number  = list(range(0,10))
        random.shuffle(number)
        OTP = ''.join(str(i) for i in number[:4])
        return OTP
    
    @classmethod
    def send_otp(cls,pro = '',status=''):
        """ This Method is to generate otp """
        if status == 'empty':
            pass
        else:
            cls.OTP_VALUE = cls.otp_generator()
            Encry_otp = base64.b64encode(cls.OTP_VALUE.encode()).decode()
            otp_snt_time = str(datetime.now().replace(microsecond=0))
            AntivirusUtility.db_management("update Status_Master set otp = '"+Encry_otp+"',otp_snt_time='"+otp_snt_time+"' ")
        if cls.Lic_tuple:
            Lic_API_Data, Lic_txt, Licence_old_key = cls.Lic_tuple
        else:
            pass
        if pro == 'licence_popup':
            pass
        else:
            Lic_API_Data = cls.api_request(ApiLinks.LIC_VERIFY % (cls.MAC_Address, Lic_txt, cls.OTP_VALUE))
            cls.Lic_tuple = tuple((Lic_API_Data['response_json'],Lic_txt, Licence_old_key))
        
    @classmethod
    def verify_otp(cls,otp_entered):
        """ This Method is helps to verify OTp """
        otp, otp_snt_time = AntivirusUtility.db_management("select otp,otp_snt_time from Status_Master")[0]
        Lic_API_Data, Lic_txt, Licence_old_key = cls.Lic_tuple
        Decry_otp = base64.b64decode(otp.encode()).decode()
        otp_snt_time = datetime.strptime(otp_snt_time,"%Y-%m-%d %H:%M:%S")
        current_time = datetime.now().replace(microsecond= 0)
        actual_seconds = (current_time - otp_snt_time).total_seconds()
        
        if otp_entered == Decry_otp:
            if actual_seconds>1800:
                return '[color=#ff073a]OTP has Expired'
            else:
                AntivirusUtility.db_management("update auth set serial_key = '"+cls.serial_key+"',license = '"+Lic_txt+"',remaining_days = '"+str(Lic_API_Data['remaining_days'])+"' ")
                Product_information = cls.api_request(ApiLinks.PROD_INFO % (Lic_txt, cls.Oper_System, cls.MAC_Address, Version))
                cls.Licence_check = True
                cls.license_key = Lic_txt
                cls.lickey_status = True
                cls.remaining_days = Lic_API_Data['remaining_days']
                cls.auth_table_config()
                cls.initial_loads()
                cls.lickey_status = '[color=#51ff0d]* Licence Verified'
                # cls.Licence_check = True
                return True
        else:
            return "[color=#ff073a]Please Enter a Valid OTP"
        
    
    @classmethod
    def licence_popup_func(cls,License_txt):
        
        """ 
        This Method to handle License Popup function like verify license , sent OTP, check license valid or not print msg,
        Verified, Already verified, invalid, expired license 
        """
        
        if License_txt == "" :
            GeneralMethods.lickey_status = "[color=#ff073a]* Enter License Key ..!"
            return False
        else:pass
        cls.send_otp('licence_popup')
        Lic_txt = License_txt.strip()
        
        auth_data = AntivirusUtility.db_management('select license, Expiry_Date, serial_key from Auth')
        if auth_data:
            Licence_old_key, Expiry_Date, serial_key = auth_data[0]
        else:
            Licence_old_key, Expiry_Date, serial_key = [], [], ''

        xx_lic = ' '
        if serial_key:
            if len(Lic_txt)*'X' == len(serial_key)*'X':
                xx_lic = len(Lic_txt)*'X'
            else:
                pass
        else:
            pass
        

        ##### The Below Statement for GET License Key
        if AntivirusUtility.check_Internet_req():
            if xx_lic not in Lic_txt and Lic_txt:
                try:
                    return_data = cls.api_request(ApiLinks.GET_LIC % (Lic_txt))
                    return_data = return_data['response_json']
                    print(return_data)
                    package_name = return_data['package_name']
                    # package_name = f"Dima {package_name.capitalize()}"
                    
                    if package_name == "BASIC":
                        pass
                    else:
                        GeneralMethods.lickey_status = "[color=#ff073a]Package Mismatch Invalid Key !"
                        return

                    cls.usr_email = return_data['email']
                    return_data = return_data['license_key']
                    cls.serial_key = Lic_txt

                    if return_data in ['Not Found','In Active']:
                        raise Exception('')
                    else:pass
                    
                    usr_email = cls.usr_email
                    data = cls.usr_email.split('@')
                    cls.usr_email = f"{data[0][:5]}{'...'}@{data[-1][:11]+'.'+data[-1].split('.')[-1] if len(data[-1])>10 else data[-1]}"
                    cls.email_count = 25-len(cls.usr_email) if len(cls.usr_email)<25 else 1

                    if return_data:
                        if return_data == Licence_old_key and type(cls.Auth_table_dict['remaining_days']) == int:
                            GeneralMethods.lickey_status = "[color=#51ff0d]* Already Verfied"
                            return
                        else:
                            Lic_txt = return_data
                    else:
                        cls.lickey_status = '[color=#ff073a]* invalid License Key'

                except Exception as exe:
                    try:
                        return_data = return_data['license_key'] if type(return_data) == dict else return_data
                        if return_data == 'In Active':
                            cls.lickey_status = f'[color=#ff073a]* {return_data} Licence Key'
                        elif return_data == 'Not Found':
                            cls.lickey_status = f'[color=#ff073a]* invalid License Key'
                        else:
                            cls.lickey_status = '[color=#ff073a]* Internal Error'
                        return
                    except:
                        cls.lickey_status = '[color=#ff073a]* Internal Error'
                        return

            else:
                if 'XXXXXX' in Lic_txt:
                    cls.lickey_status = "[color=#51ff0d]* Already Verfied"
                    return
                else:pass

        else:
            cls.lickey_status = '[color=#ff073a]* No Internet'

        #### THE BELOW STATEMENT TO CHECK AND CERIFY LICENSE 
        if Lic_txt !=  serial_key  or  Licence_old_key == [] or type(cls.Auth_table_dict['remaining_days']) != int :

            if AntivirusUtility.check_Internet_req(): 
                Lic_API_Data = cls.api_request(ApiLinks.LIC_VERIFY % (Lic_txt, cls.MAC_Address, cls.OTP_VALUE))
                status_code = Lic_API_Data.get('status_code', None)
                Lic_API_Data = Lic_API_Data.get('response_json')

            else:
                cls.lickey_status = '[color=#ff073a]* No Internet'
                return 
            

            if status_code in [200] or Lic_txt !=  serial_key and 'remaining_days' in Lic_API_Data.keys():

                if type(Lic_API_Data['remaining_days']) != str : 
                    cls.Lic_tuple = tuple((Lic_API_Data,Lic_txt, Licence_old_key))
                    Active_status = '1' if Lic_API_Data['status'] else '0' 
                    
                    if Expiry_Date:
                        AntivirusUtility.db_management('UPDATE Auth set Installed_date = "'+str(datetime.strptime(Lic_API_Data['license_st_dt'], '%d/%m/%Y'))+'",expiry_date = "'+str(datetime.strptime(Lic_API_Data['license_exp_dt'], '%d/%m/%Y'))+'",status = "'+Active_status+'"')
                    else:
                        AntivirusUtility.db_management("""
                        insert into Auth (
                            'Computer_Name','MAC_Address','Installed_date','Expiry_Date','Status','Last_Verified','current_version','Operating_System','email'
                        )VALUES(?,?,?,?,?,?,?,?,?)
                        """, (cls.Machine_Name, cls.MAC_Address, datetime.strptime(Lic_API_Data['license_st_dt'], '%d/%m/%Y'), datetime.strptime(Lic_API_Data['license_exp_dt'], '%d/%m/%Y'), Lic_API_Data['status'], str(datetime.now().date()),
                            Version, cls.Oper_System, usr_email)
                        )
                    cls.send_otp('licence_popup','empty')
                    return True
                    
                else:
                    cls.lickey_status = '[color=#ff073a]* Expired License Key'
                    return 
            
            elif Licence_old_key == Lic_txt:
                cls.lickey_status = "[color=#51ff0d]* Already Verfied"

            elif Lic_API_Data['msg']:
                cls.lickey_status = f"[color=#ff073a]* {Lic_API_Data['msg']} ?"
            else:
                return

        elif len(Lic_txt)<1:
            cls.lickey_status = "[color=#ff073a]* Enter License Key"
            
        else:
            cls.lickey_status = False
            return False
    
    @classmethod
    def software_update(cls):
        """ The function helps to download the New update file"""
        url = (ApiLinks.DOWN_LAT_VER % (platform.platform(),cls.Update_verche_json['latest_version']))
        resp = requests.get(url, stream=True)

        if resp.status_code in [200,208]:
            total = int(resp.headers.get('content-length', 0))
            return tuple((resp,total,cls.Update_verche_json['latest_version']))
        else:
            return ['Update Error'] if AntivirusUtility.check_Internet_req() else ['No Internet']
    
    @classmethod
    def path_spliter(cls, src_path, scan_type):
        """ This Method is helps to collect the path for custom and full scan"""

        cls.file_cnt = 0
        Path_List = []
        gc.collect()    
        cls.scan_status = False
        try:
            def end_loop():
                Path_List = []
                raise StopIteration

            #### THE BELOW STATEMENT IS HELPS TO SEGREGATE THE PROCESS ACCORDING TO SCAN TYPE 
            if scan_type=='full_scan':
                Act_Drivers = AntivirusUtility.get_drives()
                logging.info(f"Act_Drivers : {Act_Drivers}")
            else:
                Act_Drivers = [src_path]
            
            for src_path in Act_Drivers:
                if cls.scan_status:break
                
                ##### FOR A SINGLE FILE 
                if  os.path.isfile(src_path): 
                    check = [i if not cls.scan_status else end_loop() for i in cls.AV_WIDGETS_ACTION['ignoreList'] if i.replace('\\','/').lower() in root.replace('\\','/').lower()]
                    if check:
                        pass
                    else:
                        if cls.AV_WIDGETS_ACTION['ignorePatterns'].count(os.path.splitext(name)[-1]):
                            pass
                        else:
                            srcPath = os.path.join(root,name)
                            file_size = os.path.getsize(srcPath)/1024000

                            if file_size >= 25:
                                pass
                            else:
                                cls.file_cnt = len(Path_List)
                                Path_List.append(src_path)
                else:
                    ##### FOR MULTIPLE FILES  FILE 
                    walk_data = os.walk(src_path)
                    for root,sub,files in walk_data:
                        if cls.scan_status :
                            break
                        check = [i if not cls.scan_status else end_loop() for i in cls.AV_WIDGETS_ACTION['ignoreList'] if i.replace('\\','/').lower() in root.replace('\\','/').lower()]
                        if check:
                            pass
                        else:
                            for name in files:
                                if cls.scan_status :
                                    break
                                else:pass   

                                if cls.AV_WIDGETS_ACTION['ignorePatterns'].count(os.path.splitext(name)[-1]):
                                    pass
                                else:
                                    try:
                                        srcPath = os.path.join(root,name)
                                        file_size = os.path.getsize(srcPath)/1024000
                                        print("file_size",file_size)

                                        if file_size >= 25:
                                            pass
                                        else:
                                            cls.file_cnt = len(Path_List)
                                            Path_List.append(srcPath) 
                                    except:pass 
        except Exception as e:
            print(f"path_spliter----------------------{e}")
        finally:
            return list(set(Path_List)) if len(Path_List) else [f'{cls.dir_path}scan_with.txt']
    

    @classmethod
    def window_foreground(cls):
        pass
        # def windowEnumerationHandler(hwnd, top_windows):
        #     top_windows.append((hwnd, win32gui.GetWindowText(hwnd)))
        # if __name__ == "__main__":
        #     results = []
        #     top_windows = []
            
        #     win32gui.EnumWindows(windowEnumerationHandler, top_windows)
        #     for i in top_windows:
        #         if "DimaAV" in i[-1]:
        #             win32gui.ShowWindow(i[0],5)
        #             win32gui.SetForegroundWindow(i[0])
        #             break
    
    
#### THE BELOW CLASS IS HAVING SOME METHODS THAT IS HELPS TO PERFORM MAIN TASK OF DIMAAV APP
class AntivirusUtility():
    """ 
    AntivirusUtility class has the following Methods ( __init__, check_Internet_req, get_drives, get_removable_devices,
    antivirus_encryptor, show_notification, db_management, encryped_file_handler )
    """
    
    gc.collect() 
    def __init__(self):
        gc.collect()
        self.AV_TITLE = "Dima Antivirus"
        self.usb_remover = "RemoveDrive.exe"
        self.dir_path = GeneralMethods.dir_path
        self.AV_EXE_NAME = self.AV_TITLE+".exe"
        self.dir_path_exe = self.dir_path + self.AV_EXE_NAME
        self.DB_NAME = f"{self.dir_path}ANTIVIRUS.db"
        self.av_alert_icon = "static/images/BRAND_ICON.ico"
        self.ENCRYPTION_PATH = GeneralMethods.ENCRYPTION_PATH

        #### THE BELOW STATEMENT IS USED TO CHECK ENCRYPTION FOLDER IS ALREADY IN OR NOT 
        "" if os.path.exists(self.ENCRYPTION_PATH) else os.mkdir(self.ENCRYPTION_PATH)

        #### LOGFILES 
        log_file = self.dir_path+"AV_LEDGER.log"
        log_mode = "a" if os.path.exists(log_file) else "w"
        logging.basicConfig(
            handlers=[RotatingFileHandler(filename=log_file, mode=log_mode, maxBytes=50000000, backupCount=10)],
            level=logging.INFO, format="%(asctime)s:%(message)s", datefmt='%Y-%m-%d %H:%M:%S'
        ) 

    #### THE BLEOW METHOD IS HELPS TO CHECK INTERNET CONNECTION
    @staticmethod
    def check_Internet_req(url='http://www.google.com/', timeout=3):
        """ This Method is helps to check internet connectivity """
        try:
            a = requests.head(url, timeout=timeout)
            return 1
        except:
            logging.info("Internet-Connection Error")
            return 0
    
    #### THE BLEOW METHOD IS HELPS TO GET WINDOWS DRIVERS
    @classmethod
    def get_drives(cls):
        """ get_drives is helps to get dives in the local system """
        try:
            drives_path = []
            drps = psutil.disk_partitions()
            drives = [dp.device for dp in drps if dp.fstype == 'NTFS']
            for driv in drives:
                drives_path.append(driv.replace("\\","/"))
            return drives_path
        except:
            logging.exception(f"ERROR-MESSAGE")

    #### THE BLEOW METHOD IS HELPS TO GET REMOVABLE DEVICES
    @classmethod
    def get_removable_devices(cls):
        """ This method is used to get removable devices """
        try:
            drive_list = []
            drivebits = win32file.GetLogicalDrives()
            for d in range(1, 26):
                mask = 1 << d
                if drivebits & mask:
                    # here if the drive is at least there
                    drname = '%c:/' % chr(ord('A') + d)
                    t = win32file.GetDriveType(drname)
                    if t == win32file.DRIVE_REMOVABLE:
                        drive_list.append(drname)
            return drive_list
        except:
            logging.exception(f"ERROR-MESSAGE")

    #### THE BLEOW METHOD IS HELPS TO encrypt the viruds file
    def antivirus_encryptor(self,source_file):

        """ This method is used to Encrypt the Malicious File with PASSWORD."""
        try:
            if os.path.exists(source_file) and os.path.isfile(source_file) == True:
                logging.info(f"antivirus_encryptor Method call received.")
                # secret_pattern = f"_{self.AV_TITLE}_"
                dest_file = f"{self.ENCRYPTION_PATH}/{base64.b64encode(source_file.encode()).decode()}.zip"
            
                with pyzipper.AESZipFile(dest_file,'w', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:

                    ##### secret_password is base85 encoded form of "Dima Antivirus"
                    zf.setpassword(GeneralMethods.secret_password)
                    zf.write(source_file, basename(source_file))
                zf.close()

                try:
                    os.remove(source_file)
                except:
                    filename = source_file.split('/')[-1]
                    [p.kill() for p in psutil.process_iter() if p.name() == 'CHXSmartScreen.exe' or p.name() == filename ]
                    os.remove(source_file)

                logging.info(f"Source File Removed Successfully.")
                return True
            else:
                logging.info("File Not Found for antivirus_encryptor ")
                return False
        except Exception as ex:
            logging.exception(f"Exception in pyzipper-AES : {ex}")
            return None

    #### THE BLEOW METHOD IS HELPS TO give notifications 
    @classmethod
    def show_notification(cls,msg,state = 1,thread = True):
        "This Method is to show notifications"
        title = f'{AV_TITLE} Security Alert..!'
        icon = GeneralMethods.dir_path+ '/' +"static/images/BRAND_ICON.ico"
        tmp_path=icon.split('/s')[0]    
        if state==1:
            try:
                toast.show_toast(title,f"{msg}",icon_path=icon, duration=3,threaded=thread)
            except:
                pass
        else:
            pass
        return tmp_path

    #### THE BELOW FUNCTION IS HELPS TO INSERT, GET AND UPDATE SQLITE DATA BASED ON SQLITE3 QUERIES 
    @classmethod
    def db_management(cls,Query,data_tuple = ''):
        """ This Method Handles all the Database operations (insert, update, delete)"""
        conn = sq.connect(f"{GeneralMethods.dir_path}ANTIVIRUS.db")
        return_data = ''
        try:
            cursor = conn.cursor()
            if data_tuple:
                return_data = cursor.execute(Query,data_tuple).fetchall()
            else:
                if 'update' in Query.lower() or 'insert' in Query.lower():
                    cursor.execute(Query)
                    conn.commit()
                else:
                    return_data = cursor.execute(Query).fetchall()         
        except:
            pass

        finally:
            conn.commit()
            conn.close()      
        return return_data

    #### THE BELOW FUNCTION IS HELPS TO ACTION POPUP DATA BASED ON BUTTONS
    def encryped_file_handler(self,Action_Encrypt_Data,Process_Type):
        """ This method is handles Quarantined files it can ( Delete, restore and Ignore the files ) """
        try:  
        
            for filename in os.listdir(self.ENCRYPTION_PATH):
                status = False
                src_file = f"{self.ENCRYPTION_PATH}/{filename}"
                info = os.stat(src_file)
                # os.chmod(Action_Encrypt_Data[3], stat.S_IRWXU) 
                if filename.endswith('.zip'): 
                    with pyzipper.AESZipFile(src_file) as zf:
                        ##### secret_password is encoded form of "Dima Antivirus"
                        zf.setpassword(GeneralMethods.secret_password)
                        if zf.namelist():
                            if zf.namelist()[0] == Action_Encrypt_Data[2]:
                                if base64.b64decode(filename.split('.zip')[0].encode()).decode() == Action_Encrypt_Data[3]:
                                    if Process_Type == 'Restore':
                                        my_secrets = zf.read(zf.namelist()[0])
                                        f = open(Action_Encrypt_Data[3],'wb').write(my_secrets)
                                        self.db_management("""update user_action set Action = 'Restore' where id = '"""+str(Action_Encrypt_Data[0])+"""'""")
                                        status = True

                                    elif Process_Type == "Delete":
                                        self.db_management("""update user_action set Action = 'Delete' where id = '"""+str(Action_Encrypt_Data[0])+"""'""")
                                        status = True
                                    
                                    else:
                                        my_secrets = zf.read(zf.namelist()[0])
                                        f = open(Action_Encrypt_Data[3],'wb').write(my_secrets)
                                        self.db_management("""update user_action set Action = 'Ignore' where Hash_id = '"""+str(Action_Encrypt_Data[4])+"""'""")
                                        self.db_management("""update offline_master set Ignore_Action = 'Ignore' where id = '"""+str(Action_Encrypt_Data[4])+"""'""")
                                        status = True
                                        pass
                                else:
                                    pass
                else:
                    os.remove(src_file)
                if status:
                    zf.close()
                    os.remove(src_file)
                else:pass
        except Exception as exception:
            print('encryped_file_handler-->',exception)
    
