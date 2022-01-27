""" 
    The Antivirus Software to detect and clean the infected files from your computer.
"""
__authors__ = "DIMA Production Team"
__copyright__ = "Copyright 2020, dimabusiness.com"
__version__ = "v2.3"
__maintainer__ = "DIMA Production Team"
__status__ = "Production"

import os , socket 
from random import randint
import sys
import subprocess
import gc
import time
import mouse
import socket
import json
import shutil
import psutil
import logging
import platform
from PIL import Image
from pathlib import Path
from zipfile import ZipFile
from threading import Thread
from plyer import filechooser
from pystray import Icon, Menu, MenuItem
from datetime import datetime, timedelta, date
from logging.handlers import RotatingFileHandler

from Empx import proxy
pxy = proxy.Proxy()

#### EXECUTABLE FILE NAME VARIABLE AND VALUE 
AV_TITLE = "Dima Antivirus" 
AV_EXE_NAME = AV_TITLE+".exe"

#### to find current directory path
dir_path = sys.argv[0].replace('\\','/').replace(AV_EXE_NAME,'') if AV_EXE_NAME in sys.argv[0] else sys.argv[0].replace('\\','/').replace('antivirus_gui.py','')

### FILE NAMES FOR CREATION AND PROCESSING
AV_WIDGETS = "widgets.json"
DB_NAME = f"{dir_path}ANTIVIRUS.db"
SCAN_WITH =  f"{dir_path}scan_with.txt"
log_file = f"{dir_path}AV_LEDGER.log"

#### to find temp folder path
on_hide_filename = str(os.path.join(Path.home(), r"AppData\Local\Temp\{}_on_hide".format(AV_TITLE)))

#### SCAN_WITH ANTIVIRUS TEXT FILE CREATION 
' ' if os.path.exists(SCAN_WITH) else open(SCAN_WITH,'w').close()

#### utils file import for performing certain operations
from Empx.utils import AntivirusUtility as AU, GeneralMethods as GM, ApiLinks as AL

GM.dir_path = dir_path 
GM.ENCRYPTION_PATH = f"{dir_path}Dima_Vault"

#### backend file import for performing scanning functions
from Empx.antivirus_backend import AntivirusBackend as ABac
Ant_ins = AU()\

uni_Query = """
            select a.id,a.Date_Time,File_Name,Source_Path,Hash_ID,Threat_Name from user_Action a
            left join Offline_Master b on a.Hash_ID = b.id
            WHERE Malicious = '1'and Action is NULL order by a.date_time desc
            """

if sys.argv[-1] == 'from_install':
    proxy.Proxy.exclusive_path(dir_path,"Add","/D", AV_TITLE)
    sys.exit()
#### the below script performs while uninstalling the software helps to unzip al the quarantined to their previous locations 
if sys.argv[-1] == 'from_uninstall':
    Restore_Data = Ant_ins.db_management(uni_Query) 
    for row in Restore_Data:
        AU().encryped_file_handler(row,'Restore')
    proxy.Proxy.exclusive_path(dir_path,"Remove","/E", AV_TITLE)
    sys.exit()

else:
    pass

#### LOG FILE CREATION STARTS
log_mode = "a" if os.path.exists(log_file) else "w"
logging.basicConfig(
    handlers = [RotatingFileHandler(filename = log_file, mode = log_mode, maxBytes = 50000000, backupCount = 10)],
    level = logging.DEBUG, format="%(asctime)s:%(message)s", 
    datefmt = '%Y-%m-%d %H:%M:%S'
)
log_history = log_file

#### JSON FILE CREATION FOR THREAT ACTIONS, REAL TIME PROTECTION, BROWSE OPTION, STATUS OF FULL SCAN AND CUSTOM SCAN
json_dict = {'threat_action': 'quarantine', 'real_time_protection': 'on',
             'browse_option': 'folder', "full_scan": "0", "custom_scan": "0"}

#### Main Program Starts 
try:  
    #### LOADING JSON FILE FOR WIDGETS 
    JSN_PATH = f"{dir_path}static/json_files/"
    AV_WIDGETS_ACTION = json.load(open(f"{JSN_PATH}{AV_WIDGETS}",'r'))

    " Database Connectivity "

    if os.path.exists(DB_NAME) :
        pass
    else:  
        for Query in AV_WIDGETS_ACTION['MSSQL_Table_Creation']:
            AU.db_management(str(Query))
            if 'Status_Master' in Query:
                AU.db_management(
                                """insert into Status_Master (Browse_Option, Full_Scan, Custom_Scan, Real_Time_Protection, Threat_Action, Header_Msg)values(?,?,?,?,?,?)""",
                                tuple(AV_WIDGETS_ACTION['Status_Master_Tabledata'])
                                )
            else:
                pass

    #### INSTANCE FOR GENERAL VERSION AND LOAD aUTH TABLE DATA
    GM_instance = GM()
    ABac.AV_WIDGETS_ACTION = AV_WIDGETS_ACTION
    GM.AV_WIDGETS_ACTION = AV_WIDGETS_ACTION
    GM.Auth_Fields = AV_WIDGETS_ACTION['Auth_Fields']
    GM.auth_table_config()
    GM.machine_attributes()
    GM.license_key = GM.Auth_table_dict['license']
    GM.initial_loads()
    
    """ Kivy libraries """
    
    #### THE CONDITION TO PERFORM ALL THE WINDOW VERSIONS
    if 'Windows-7' in platform.platform():
        pass  
    else:
        os.environ['KIVY_GL_BACKEND'] = 'angle_sdl2'
    
    # os.environ["KIVY_NO_FILELOG"] = "1"
    # os.environ["KIVY_NO_CONSOLELOG"] = "1"
    
    from kivy import Config
    Config.set('graphics', 'multisamples', '0')
    
    #### CONFIG FOR HIDDING KIVY LOADING SCREEN 
    Config.set('graphics', 'window_state','hidden')
    Config.set('input', 'mouse', 'mouse,multitouch_on_demand')
 
    from kivymd.app import MDApp
    from kivy.lang import Builder
    from kivy.factory import Factory
    from kivy.uix.button import Button
    from kivy.core.window import Window
    from kivymd.uix.picker import MDDatePicker
    from kivy.uix.relativelayout import RelativeLayout
    from Empx.utilskv import Table, OTP_popup, OTP_TXTInput, Action_popup, HovBtn

    #### THE FUNCTION FOR INITIAL WINDOW SIZE AND BORDER LESS 
    Window.borderless = True 
    Window.size = (940,600)

    #### THE BELOW STATEMENT IS HELPS TO LOADING A  .KV FILE FROOM STATIC FOLDER
    Builder.load_file(dir_path+'static/kivy_files/main.kv')
                        
    #### THE BELOW CLASS IS FOR DOING TEXTINPUT RELATED FUNCTIONS 
    class DragOption(Button):
        """
        DragOption class is to perform app Dragging behavior,
        There are three important event calling methods are used in this class,
        
        on_touch_up:change the mouse cursor to "arrow", 
        when you release your finger from the mouse it will execute
        
        on_touch_down:change the mouse cursor to "hand", 
        the method is also calculates the mouse point (touch_x,touch_y) values   
        
        on_touch_move:it is a main function it should trigger only when you hold the mouse button and move,
        it calculates the current mouse position subtract with touch_x.touch_y, then apply those values to
        windows top and left 
        
        """
        
        def on_touch_up(self, touch):
            Window.set_system_cursor('arrow')
     
        def on_touch_down(self, touch):
            Window.set_system_cursor('hand')         
            self.window_left, self.window_top = Window.left, Window.top 
            self.touch_x, self.touch_y = mouse.get_position()[0], mouse.get_position()[1]
            return super(DragOption, self).on_touch_down(touch)

        def on_touch_move(self, touch):
            try:
                horizontal_movement = mouse.get_position()[0] - self.touch_x
                Vertical_movement = mouse.get_position()[1] - self.touch_y 
                if Window.height >= 600 and Window.height <= 650:
                    Window.top = self.window_top + Vertical_movement
                    Window.left = self.window_left + horizontal_movement
                else:
                    pass
            except:
                pass
            return super(DragOption, self).on_touch_move(touch)
    
            
    class AntivirusGUI(RelativeLayout):
        
        """
        AntivirusGUI is a main class for Antivirus application it has the following methods ( __init__, lic_remain_days, popup_open,
        popup_open, start_tray_thread, system_tray_func, Licence_Detector, id_state_handler, default_os_functions, real_time_protection, 
        registry_check_status, software_update, after_update_fun, History_options, last_scan, lastactivity_history_action_show, Browse_option, 
        datepicker, progress_bar_widgets_position, header_label, progressbar_widgets_scanning_calc, full_scan, custom_scan, stop_scan_classmethod, 
        log_downloader, download_file_view, button_status ) 
        
        """
        #### CLASS VARIABLES WE CANT CHANGE THE VALUES DYNAMICALLY (FOR ACCESING BUTTON AND BACKGROUND IMAGES)
        font_path = f"{dir_path}static/fonts/"
        IMG_PATH = f"{dir_path}static/images/"
        JSN_PATH = f"{dir_path}static/json_files/"
        settings_status = False
        av_version = f"- {__version__ }" 
        
        for key,value in AV_WIDGETS_ACTION['AV_Image_names'].items():
            vars()[key] = f"{IMG_PATH}{value}"

        def __init__(self,**kwargs):
            super().__init__(**kwargs)
            #### INSTANCE VARIABLES HELPS TO  CHANGE THE VALUES DYNAMICALLY ( INSIDE THE CLASS )
            self.from_date, self.to_date = date.today(), date.today()
            self.date_type, self.browse_option,self.license_hash_check = '', '',True 
            self.browse_dirname, self.estimated_time, self.license_key_msg = '', '', False
            self.scan_file_list, self.Quarantine_hide_msg, self.update_after_icon = [], 0 , False
            self.hideloop_reducer, self.threat_count, self.monitor_count = 0,0,0
            self.history_line, self.length_of_history,self.LC_Count = 0,0,0
            self.AV_WIDGETS_ACTION, self.duration = AV_WIDGETS_ACTION, 1
            self.ids.to_date_textinput.text = str(self.from_date)
            self.ids.from_date_textinput.text = str(self.to_date)
            self.downloads_dir = str(os.path.join(Path.home(), "Downloads"))
            self.current_value, self.initial_value, self.Lic_Excnt= '', '', 0
            self.hide_funct, self.tray_in_start, self.Licence_Activity  = '','', True

            #### THE BELOW FUNCTION HELPS TO LAST SCAN FUNCTION TO GET LAST SCAN DATA
            self.last_scan()
            
            #### THE BELOW STATEMENT IS TO LOAD JSON FILE TO VARIABLE TO MAINTAIN WIDGETS STATE
            id, browse_option, full_scan, custom_scan, real_time_protect, threat_act, Header_Msg, otp, otp_snt_time,ps = AU.db_management("select * from Status_Master;")[0]
            self.AV_OPTIONS = {"browse_option": browse_option, "full_scan": full_scan, "custom_scan": custom_scan,
                               "real_time_protection": real_time_protect, "threat_action": threat_act, 'Header_Msg': Header_Msg}
            self.browse_option = self.AV_OPTIONS['browse_option']
            # ABac().monitoring_interupt_fun('set')
    
            #### THE BELOW CALL FOR ACTIVATING SYSTEM TRAY
            self.start_tray_thread()
            
            #### THE BELOW FUNCTION CALL IS TO LOAD LICENSE TEXT FILE DATA
            self.startup = True
            self.Licence_Detector()
            
            ####  THE BELOW LINE FOR ASSURING FULL SCAN AND CUSTOM SCAN SHOULD BE IN OFF POSITION 
            AU.db_management("update Status_Master set Full_Scan ='0', Custom_Scan = '0'") 
            
            ### GUIS ALL WIDGETS OPACITY, DISABLE AND ENABLE OPTIONS WHILE STARTUP
            self.button_status(self.AV_WIDGETS_ACTION['DimaAV_App_Startup'])
            
            #### THE BELOW STATEMENT IS TO CREATE LAST SCAN CSV FILE AND COUNT THE DATES 
            file_open = AU.db_management("select * from scan_history")
            self.length_of_history = len(file_open)

            #### THE BELOW STATEMENT IS TO MAINTAIN FILE AND FOLDER CHECKBOX STATE
            if self.AV_OPTIONS['browse_option'] == 'File':
                self.button_status(self.AV_WIDGETS_ACTION['folder_box_tick_hide'])
            else:
                self.button_status(self.AV_WIDGETS_ACTION['file_box_tick_hide'])
                    
            #### THE BELOW FUNCTION IS TO MAINTAIN REAL TIME PROTECTION STATE WHILE GUI START UP
            if GM.Auth_table_dict:
                self.AV_OPTIONS['real_time_protection'] = self.AV_OPTIONS['real_time_protection'] if GM.Auth_table_dict['license'] else  'off' 
                        
            #### THE BELOW STATEMENT IS TO SAVE LAST SCAN COUNT
            self.history_line = self.length_of_history

            #### THE BELOW THREAD IS FOR LISIONING SCAN WITH FILE PATH IS IN THE TXT FILE OR NOT
            reg_thread = Thread(target=self.registry_check_status,daemon = True)
            reg_thread.name = "ScanWith_Reg_Thread"
            reg_thread.start()
            
            if type(GM.Auth_table_dict['remaining_days']) != int:
                self.lastactivity_history_action_show('settings')
            else:pass
                    
            #### FOR APP HIDDEN WHILE THE REQUEST FROM STARTUP
            if sys.argv[-1] == 'from_startup':
                if type(GM.Auth_table_dict['remaining_days']) == int :
                    self.default_os_functions('hide')  
                else: pass
            else: pass
            
            
        @classmethod
        def lic_remain_days(cls):
            """
            This Method is helps to calculate license remaining days if system is in online it gets the value from api 
            else it calculate the value from local database using license_exp_date method
            """
            try:
                Lic_API_Data = GM.api_request(AL.LIC_VERIFY % (GM.Auth_table_dict['mac_address'], GM.Auth_table_dict['license']))
                return Lic_API_Data['response_json']['remaining_days']
            except:
                GM.license_exp_date()
                GM.auth_table_config() 
                return GM.Auth_table_dict['remaining_days']
            
        @classmethod
        def popup_open(cls):
            """
            This Method is helps to open a Popup Windows that we have used in this project,
            it just reduce the memory that has consummed by Popup Windows 
            """
            Action_root = Factory.Action_popup()
            GM.close_popup(Action_root)
            Action_root.open()
            
        ##### start system tray thread
        def start_tray_thread(self): 
            """" 
            This Method is used to create a system try function Thread
            """   
            tray_thread = Thread(target = self.system_tray_func,daemon=True)
            tray_thread.name = "system_tray_thread"
            tray_thread.start()
            return
        
        #### Create system tray DimaAV icon  
        def system_tray_func(self):
            """" 
            This Method is used to create a system try function 
            we can switch on and off the real time protection through system tray  
            """
            image = Image.open(f"{dir_path}static/images/BRAND_ICON.ico")
            if type(GM.Auth_table_dict['remaining_days']) == int :
                lic_state_tray = True
            else:
                lic_state_tray = False
            
            if self.AV_OPTIONS['real_time_protection'] == 'on' :
                self.rtp_on = True
                self.rtp_off = False
            else:
                self.rtp_on = False
                self.rtp_off = True

             #####  add menu item function
            def rtp_on_func(icon):
                if type(GM.Auth_table_dict['remaining_days']) == int :
                    if self.AV_OPTIONS['real_time_protection'] == 'on': pass
                    else:
                        self.rtp_on = True
                        self.rtp_off = False
                        self.real_time_protection(pro_type = 'sys_tray_on')
  
            def rtp_off_func(icon):
                if type(GM.Auth_table_dict['remaining_days']) == int :
                    if self.AV_OPTIONS['real_time_protection'] == 'off': pass
                    else:
                        self.rtp_on = False
                        self.rtp_off = True
                        self.real_time_protection(pro_type = 'sys_tray_off')

            def open(icon):
                GM.window_foreground()
                if self.hide_funct == 'hide':
                    self.hide_funct = ''
                else: pass

            def close_DimaAV(icon):
                self.icon_obj.stop()
                os._exit(0)

            ##### create tray icon object
            self.icon_obj = Icon("Tray_image", 
                                icon=image, 
                                title="Dima Antivirus-Monitor",
                                menu=Menu(
                                        MenuItem('Open', lambda : open(self.icon_obj), visible = False ,default=True ),
                                        MenuItem('Real_time Protection ', Menu(MenuItem(' ON ',lambda : rtp_on_func(self.icon_obj) ,checked=lambda MenuItem: self.rtp_on),
                                                    MenuItem(' OFF ',lambda : rtp_off_func(self.icon_obj) ,checked=lambda MenuItem: self.rtp_off),)) if lic_state_tray  else MenuItem('Enter Your License Key', lambda : open(self.icon_obj)),
                                        MenuItem('Turn off', lambda : close_DimaAV(self.icon_obj) ),))

            ##### system tray run section  initialise
            self.icon_obj.run()
            return
        
        
        def Licence_Detector(self):
            """
            This method is like checker it runs continuesly with 1 sec delay it checks Valid license, expired license and  duplicate license 
            based on the conditions its changes the value with one second delay it maintains the following things (Auth table in database, 
            monitoring on and off button, Headers, Realtime protection Thread, Quarantine Popup disabled functions, full and custom scan start, stop buttons)
            """
            try:
                if type(GM.Auth_table_dict['remaining_days']) == int:
                    self.LC_Count+=1
                    if self.LC_Count == 1 or GM.Licence_check :
                        if self.AV_OPTIONS['real_time_protection'] == 'off' and not self.startup:
                            self.AV_OPTIONS['real_time_protection'] = 'on'
                            GM.Licence_check = False
                        else:pass
                        if GM.Licence_check :
                            self.ids['monitoring_button_on'].disabled = False
                            self.ids['monitoring_button_off'].disabled = False
                            self.AV_OPTIONS['real_time_protection'] = 'on'
                        else:pass
                        
                        GM.Licence_check = False
                        self.license_key_msg, self.startup = False, False
                        self.ids['lic_remain_days'].text = f"License Expires in {GM.Auth_table_dict['remaining_days']} Days"
                        self.button_status(self.AV_WIDGETS_ACTION['license_verified'])
                        self.real_time_protection('startup')
                        self.rtp_on, self.rtp_off = True, False 
                        self.ids["Licence_key_msg"].opacity = 0
                    
                        Ant_ins.db_management("update Status_Master set Real_Time_Protection = '"+(self.AV_OPTIONS["real_time_protection"])+"'")    
                        self.lastactivity_history_action_show('last_activity')
                        self.Lic_Excnt = 0
                        self.icon_obj.stop()
                        self.start_tray_thread()
                        
                    else:pass
                else:

                    self.Lic_Excnt+=1
                    if self.Lic_Excnt == 1:
                        if GM.Auth_table_dict['remaining_days'] == 'Empty' or not GM.Auth_table_dict['remaining_days'] :
                            self.ids["Licence_key_msg"].opacity = 1
                            self.license_key_msg = True
                            self.id_state_handler('Without_Licence_ids')
                            self.button_status(self.AV_WIDGETS_ACTION['license_notverified'])
                            self.ids['monitoring_button_on'].disabled = True
                            self.ids['monitoring_button_off'].disabled = True   
                            
                        # elif GM.Auth_table_dict['remaining_days'] == 'Duplicate':
                        #     self.lastactivity_history_action_show('settings')
                        #     GM.licence_interrupt = False
                            
                        #     self.AV_OPTIONS['real_time_protection'] = 'off'
                        #     self.real_time_protection('startup')
                        #     self.button_status(self.AV_WIDGETS_ACTION['license_notverified'])
                        #     self.id_state_handler('duplicate_Licence_ids')
                        #     AU.db_management("delete from Auth")
                        #     AU.db_management("insert into Auth (remaining_days)values('Duplicate')")
                        #     self.button_status(self.AV_WIDGETS_ACTION['license_notverified'])
                        #     GM.initial_loads()
                            
                        #     GM.auth_table_config()
                        #     self.scan_status = True                            
                        #     self.license_key_msg = True
                        #     self.ids["Licence_key_msg"].opacity = 1    
                        #     self.ids['lic_remain_days'].text = 'Duplicate License'
                        #     self.id_state_handler('full_scan_empty_progressbar')
                        #     self.ids['monitoring_button_on'].disabled = True
                        #     self.ids['monitoring_button_off'].disabled = True
                                 
                        elif GM.Auth_table_dict['remaining_days'] =="Expired":
                            self.real_time_protection('startup')
                            self.id_state_handler('Zero_remain_days')
                            self.ids["Licence_key_msg"].opacity = 1
                            self.ids['lic_remain_days'].text = 'License Expired'
                            self.license_key_msg = True
                            self.lastactivity_history_action_show('settings')
                            
                        else:pass
                        self.LC_Count = 0

                    else:pass
                                              
            except Exception as e:
                print(f"Licence_Detector ------------------> {e}")
                
        def id_state_handler(self,key):
            """ This Method is used to execute the values that i have saved in json file """

            for i in self.AV_WIDGETS_ACTION[key]:
                exec(i)
            
        #### THE BELOW METHOD IS TO TO ACCESS DEFAULT OS FUNCTIONS
        def default_os_functions(self,fun_type):
            
            """
            This Method is used to operate a default OS(Operating system) function like minimize and Hide
            """
            
            #### THE BELOW CLASS IS TO MINIMISE THE CURRENT WINDOW
            if fun_type == 'minimize':
                MDApp.get_running_app().root_window.minimize()
            else:    
                self.hideloop_reducer += 1
                
                #### THE BELOW STATEMENT IS TO REGULATE THE FUNCTION PROCESS
                if self.hideloop_reducer%2 != 0:
                    Window.hide()
                    #### THE BELOW STATEMENT IS TO CREATE ON_HIDE_FILE
                    open(on_hide_filename,'w').close()
                    self.hide_funct = 'hide'
                else:
                    self.hideloop_reducer = 0
                
                while self.hide_funct == 'hide' and os.path.isfile(on_hide_filename):
                    time.sleep(1)
                else:
                    """ IT'S BETTER TWO CALL SHOW() TWICE."""
                    Window.show()
                    Window.show()
                    GM.window_foreground()
                    # self.hideloop_reducer = 0
                    self.hide_funct = ''
                    return
                
            
        #### THE BELOW METHOD FOR ON AND OFF THE REAL_TIME_PROTECTION
        def real_time_protection(self,pro_type = '',lic = False):
            """ 
            This Method is to maintain the state of monitoring button and headers then background,
            monitoring process based on database pre data and custom data 
            """
            def state(status):
                if status == 'on':

                    ins = ABac()
                    real_time = Thread(target = ins.antivirus_monitor,daemon = True)
                    real_time.name = "Real_Time_Protection_Thread"
                    real_time.start()

                    av_watchdog_D_thread = Thread(target=ins.av_watchdog,args=['Downloads'])
                    av_watchdog_D_thread.name = 'av_watchdog_D_thread'
                    av_watchdog_D_thread.start()

                    av_watchdog_thread = Thread(target=ins.av_watchdog)
                    av_watchdog_thread.name = 'av_watchdog_thread'
                    av_watchdog_thread.start()

                    self.id_state_handler('real_time_pro_on_ids')
                    if type(GM.Auth_table_dict['remaining_days']) == int:
                        pass
                    else:
                        self.id_state_handler('Zero_remain_days')
                else:
                    self.id_state_handler('real_time_pro_off_ids')
                    if type(GM.Auth_table_dict['remaining_days']) == int:
                        pass
                    else:
                        self.id_state_handler('Zero_remain_days')
                        
                return

            if pro_type == 'sys_tray_on' or pro_type == 'sys_tray_off':
                if pro_type == 'sys_tray_on':
                    self.AV_OPTIONS['real_time_protection'] = 'on'
                    ABac().monitoring_interupt_fun('on')
                    state('on')
                    Ant_ins.db_management("update Status_Master set Real_Time_Protection = '"+(self.AV_OPTIONS["real_time_protection"])+"'") 
                else:
                    self.AV_OPTIONS['real_time_protection'] = 'off'
                    ABac().monitoring_interupt_fun('off')
                    state('off')
                    Ant_ins.db_management("update Status_Master set Real_Time_Protection = '"+(self.AV_OPTIONS["real_time_protection"])+"'") 
            else:
                if pro_type == 'startup':
                    if self.AV_OPTIONS['real_time_protection'] == 'on':
                        state('on')
                        ABac().monitoring_interupt_fun('on')
                    else:
                        state('off')
                        ABac().monitoring_interupt_fun('off')

                elif self.AV_OPTIONS['real_time_protection'] == 'off':
                    self.rtp_on = True
                    self.rtp_off = False  
                    self.icon_obj.update_menu()
                    self.AV_OPTIONS['real_time_protection'] = 'on'
                    ABac().monitoring_interupt_fun('on')
                    state('on')
                    Ant_ins.db_management("update Status_Master set Real_Time_Protection = '"""+(self.AV_OPTIONS["real_time_protection"])+"""'""")
                else:
                    self.rtp_on = False
                    self.rtp_off = True
                    self.icon_obj.update_menu()
                    
                    self.AV_OPTIONS['real_time_protection'] = 'off'
                    ABac().monitoring_interupt_fun('off')
                    state('off')
                    Ant_ins.db_management("update Status_Master set Real_Time_Protection = '"""+(self.AV_OPTIONS["real_time_protection"])+"""'""")
            return
        
        #### THE BELOW METHOD IS TO START CUSTOM SCAN FROM SCAN WITH OPENAV(RIGHT CLICK) OPTION
        def registry_check_status(self):  
            """ This Method is to run licence detector method scan with method 1 sec intervel """
            
            gc.collect()
            def registry_check(dir_name):
                self.browse_dirname=dir_name
                if self.AV_OPTIONS['full_scan'] == '0':
                    if self.AV_OPTIONS['custom_scan'] == '0':
                        self.ids['browse_path_text'].text=self.browse_dirname
                        Window.raise_window()
                        if type(GM.Auth_table_dict['remaining_days']) == int : 
                            self.custom_scan()
                        else:
                            pass
                    else:
                        AU.show_notification("Custom-Scan Process is already running !!")
                else:
                    AU.show_notification("Full-Scan Process is already running !!")

                return
            #### THE BELOW WHILE LISIONER FOR OPENAV OPEN WITH METHOD
            count = 0
            while True:
                time.sleep(1)
                self.Licence_Detector() 
                
                if GM.update_label_status:
                    self.software_update()
                else:pass
                
                if self.update_after_icon:
                    if count:
                        self.ids['after_update_btn'].opacity = 0.5
                        count = 0
                    else:
                        self.ids['after_update_btn'].opacity = 1
                        count = 1
                    
                
                self.current_value = open(SCAN_WITH,'r').read()
                self.current_value  = self.current_value if os.path.exists(self.current_value) else self.current_value[:-1]
                if self.initial_value != self.current_value:
                    try:os.unlink(on_hide_filename)
                    except:pass
                    empty_string = self.current_value
                    registry_check(empty_string)
                    
                    self.initial_value, self.current_value = '', ''
                    open(SCAN_WITH,'w').write('')
                else: 
                    pass
            return
        
        def software_update(self):
            """ This Method is working while software update download it shows current percentage of downloading process MB value """
            try:
                DIV_VALUE = 1048576
                update_data = GM.software_update()
                
                if len(update_data)>1:
                    self.lastactivity_history_action_show('last_activity')
                    self.ids['update_button'].disabled = True
                    GM.ready_to_install = True
                    Total_File_Size =update_data[1]/DIV_VALUE
                    Latest_Version = update_data[-1]
                    def current():
                        GM.update_label_status=False
                        fname = "Dima Antivirus.zip"
                        size_b = 0
                        dot_regulator = 0
                        AU.show_notification(f"{Latest_Version} Downloading Starts")
                        with open(fname, 'wb') as file:
                            for data in update_data[0]:
                                size = file.write(data)
                                size_b+=size
                                SIZE_MB = size_b/DIV_VALUE
                                SIZE_IN_PER = (SIZE_MB/Total_File_Size)*100
                                self.ids['Up_Down_Static'].text = f"{Latest_Version} is Downloading......"
                                self.ids['Up_Down_Dynamic'].text = f"{round(Total_File_Size,1)} MB Total, {round(SIZE_IN_PER,0)} % Complete...."
                                
                        with ZipFile(f"{dir_path}Dima Antivirus.zip", 'r') as zip:
                            zip.extractall()
                        
                        self.ids['Up_Down_Static'].text = ''
                        self.ids['Up_Down_Dynamic'].text = ''
                        self.ids['Up_Down_after_txt'].text = "Click to Install Updates"
                        self.ids['after_update_btn'].disable = False
                        self.ids['after_update_btn'].opacity = 1
                        
                        try:os.remove(f"{dir_path}Dima Antivirus.zip")
                        except:pass
                        self.update_after_icon = True
                        AU.show_notification(f"{Latest_Version} Downloaded Ready to Install")
                        GM.window_foreground()
                        
                    software_update_thread = Thread(target=current)
                    software_update_thread.name = 'software_update_thread'
                    software_update_thread.start()
                else:
                    self.ids['Up_Down_Dynamic'].text = update_data[-1]
                    
            except Exception as exe:
                print('software_update-->',exe)
            
        def after_update_fun(self):
            """
            Once the file( software update ) getting downloaded then this method will execute it move the U
            R_Pro_Handler exe to Dima Antivirus folder then stsrt the file before the current exe get killed
            """
            try:
                Architecture = platform.architecture()[0]
                if self.update_after_icon:
                    time.sleep(1)
                    try:
                        os.remove(f"{dir_path}UR_Pro_Handler.exe")
                        shutil.move(f"{dir_path}Dima Antivirus/{Architecture}/UR_Pro_Handler.exe",f"{dir_path}")
                    except:pass
                    AU.show_notification("Installation Starts Don't Turn off Your Computer \nDima Antivirus Appication leave now ")
                    time.sleep(1)
                    subprocess.Popen([f'{dir_path}/UR_Pro_Handler.exe', 'AV_Update'])
                    sys.exit()
            except Exception as exe:
                print('after_update_fun--->',exe)
                
        
        #### THE BELOW METHOD IS TO LAST ACTIVITY HISTROY ARROW OPTIONS
        def History_options(self,motion):
            """ 
            This Method is helps to enable and disable the arrow marks that is in last activity window,
            we can change the previous values using this arrow buttons 
            """
            if self.length_of_history <= 1 :
                self.button_status(self.AV_WIDGETS_ACTION['history_arrow_count_1'])
            else:
                if motion == 'backward':
                    if self.history_line != self.length_of_history:
                        self.button_status(self.AV_WIDGETS_ACTION['history_data_notequal'])      
                        self.history_line += 1     
                    else:
                        self.button_status(self.AV_WIDGETS_ACTION['history_data_equal'])   
                else:
                    if self.history_line > 1:
                        self.button_status(self.AV_WIDGETS_ACTION['history_data_>1'])
                        self.history_line -= 1
                    else:
                        self.button_status(self.AV_WIDGETS_ACTION['history_data_<1'])
                self.last_scan()

        #### THE BELOW METHOD IS TO COLLECT LAST SCAN DATA AND DISPLAY IN LAST ACTIVITY MENU
        def last_scan(self):   
            
            """
            The Last scan methos is helps to calculate and save the last scanned values it may be in full scan or custom scan,
            it is also helps to chanage current state of last activity  
            """
            try:
                #### last scan csv file read operation
                file_open = AU.db_management("select * from scan_history")

                #### THE BELOW STATEMENT IS FOR LAST SCAN CSV FILE READ OPERATION
                self.length_of_history = len(file_open)
                file_data = file_open[self.history_line-1]
        
                last_id,last_date, last_scan_type, last_scan_status, last_scanned_files, last_scan_Threats, last_scan_duration ,last_scan_path= file_data
                last_date = last_date.split('.')
                
                #### THE BELOW STATEMENT IS CREATE DATE FORMAT FOR LAST SCAN
                lastscan_date = datetime.strptime(last_date[0], '%Y-%m-%d %H:%M:%S').strftime('%d/%m/%Y %I:%M %p')
                last_scan_time = datetime.strptime(last_date[0], '%Y-%m-%d %H:%M:%S')
                lastscan_time_string = str(datetime.now()-last_scan_time).split('.')[0].split(':')
                
                #### THE BELOW STATEMENT IS TO CALCULATE THE TIME STRING
                lastscan_time_string = GM_instance.time_string_calculator(lastscan_time_string)
                last_scan_Threats = 'No' if last_scan_Threats == '0' else last_scan_Threats
                last_scan_duration = GM_instance.time_string_calculator(last_scan_duration.split(':'))
                
                #### THE BELOW STATEMENT IS COLOR CHANGER FOR LAST SCAN IF SCAN NOT COMPLETES IT SHOWS IN RED 
                las_scan_color ='[color=#08fcfc]' if last_scan_status.lower() == 'c' else '[color=#FF4500]'
                
                #### THE BELOW STATEMENT IS HELPS TO ASSIGN VALUES TO THE LABELS
                self.ids['last_scan_value'].pos_hint = {'x':0.72,'y':0.1}
                self.ids['last_scan_value'].text = f"[color=#08fcfc]{lastscan_date}{las_scan_color}   {last_scan_type}"
                self.ids['threat_value'].text = f"[color=#08fcfc]{last_scan_Threats}"
                self.ids["last_scanned_files_value"].text = f"[color=#08fcfc]{last_scanned_files}"
                
                #### THE BELOW EXCEPTION HANDLING TO MAINTAIN KIVY LOG CLEAR IF KIVY IS IN THE SYSTEM
                try:
                    kivy_log_path = str(os.path.join(Path.home(), r".kivy\logs"))
                    for kivy_log_txt in os.listdir(kivy_log_path):
                        os.remove(kivy_log_path+'\\'+kivy_log_txt)
                except:
                    pass
            except:
                pass
                
                
        #### THE BELOW METHOD IS FOR MAINTAINING ACTION LAST ACTIVITY AND HISTROY MENUS
        def lastactivity_history_action_show(self,process_type):
            
            """
            This Method is a maintainer for menu totallay we have three main menus ( last Activity, Settings, History )
            This Mehtod is helps to changee to relocate the menu option according to the menu headings
            """
            gc.collect()
            if process_type == 'last_activity':
                self.button_status(self.AV_WIDGETS_ACTION['Last_activity'])
                self.ids['histroy_activity_canvas'].radius = [(0, 0), (20, 20), (20, 20), (20, 20)]
                
            elif process_type == 'settings':
                self.button_status(self.AV_WIDGETS_ACTION['settings'])
                self.ids['histroy_activity_canvas'].radius = [(20, 20), (20, 20), (20, 20), (20, 20)]
                Table.pagination_status = True
                Encry_Count = AU.db_management("""
                select count(b.id) from Offline_Master a
                left join User_Action b on a.id = b.Hash_ID where Malicious = 1 and Action is NULL and Ignore_Action is NULL
                """)[-1][-1]      
                self.Quarantine_hide_msg = 0 if Encry_Count == 0 else self.Quarantine_hide_msg
                self.ids['update_button'].disabled = True if GM.ready_to_install else False
                
                if Encry_Count != self.Quarantine_hide_msg :
                    self.ids["Quarantine_msg"].opacity = 1
                    self.ids["Quarantine_msg"].color = 1,1,1,1
                    self.Quarantine_hide_msg = Encry_Count
                    
                else:
                    self.ids["Quarantine_msg"].opacity = 0
                    self.ids["Quarantine_msg"].color = 0,0,0,0
                    
                if self.license_key_msg:
                    self.ids["Licence_key_msg"].opacity = 1
                    self.ids["Licence_key_msg"].color = 1,1,1,1
                else:
                    self.ids["Licence_key_msg"].opacity = 0
                    self.ids["Licence_key_msg"].color = 1,1,1,0
                    
                if GM.Update_Status:
                    if GM.ready_to_install:
                        pass
                    else:
                        self.ids['update_msg'].opacity = 1
                        self.ids['update_msg'].color =  1,1,1,1 
                else:
                    self.ids['update_msg'].opacity = 0
                    self.ids['update_msg'].color =  1,1,1,0 
                
            else:
                self.button_status(self.AV_WIDGETS_ACTION['Log_files'])
                self.ids['histroy_activity_canvas'].radius = [(20, 20), (20, 20), (20, 20), (20, 20)]

        #### THE BELOW METHOD IS FOR ASSIGNING BROWSE PATH
        def Browse_option(self,option):
            """ This Method is helps to Choose file or folder in custom scan palette and also to perform browse button option """
            
            try:
                if option == 'File' or option == 'Folder':
                    self.browse_option = option
                else: pass 
                if option == 'File':
                    self.button_status(self.AV_WIDGETS_ACTION['Browse_option_file'])
                    self.AV_OPTIONS['browse_option'] = 'File'
                    self.ids['browse_path_text'].text = ''

                elif option == 'Folder':
                    self.button_status(self.AV_WIDGETS_ACTION['Browse_option_folder'])
                    self.AV_OPTIONS['browse_option'] = 'Folder'
                    self.ids['browse_path_text'].text = ''

                else:
                    if self.browse_option == 'File':
                        self.browse_dirname = filechooser.open_file(title = 'Choose your path')[0]
                    else:
                        self.browse_dirname = filechooser.choose_dir(title = 'Choose your path')[0]
                    self.ids['browse_path_text'].text = self.browse_dirname
                AU.db_management("update Status_Master set Browse_Option = '"""+(self.AV_OPTIONS["browse_option"])+"""'""")
            except:
                pass
            return
            
        #### THE BELOW METHOD IS A DATEPICKER FOR OPEN A CALENDER WIDGET
        def datepicker(self,date_type):
            """ The datepicker method is for opening datepicker popups for selecting dates in history menu to download log files """
            self.date_type = date_type
            def get_date(the_date):
                if self.date_type == 'from':
                    self.from_date = the_date
                    self.ids.from_date_textinput.text = str(the_date)
                elif self.date_type == 'to':
                    self.to_date = the_date
                    self.ids.to_date_textinput.text = str(the_date)
            MDDatePicker(callback = get_date).open() ## to show calendar
            return

        #### THE BELOW METHOD IS HELPS CHANGE POSITION FOR PROGRAESS BAR WIDGETS POSTION (CUSTOM AND FULL SCAN)
        def progress_bar_widgets_position(self,scan_type):
            
            """ This function is used to switch the progressbar parameters between full scan and custom scan """
            
            progressbar_ids = [
                'progress', 'progress_value', 'estimated_time', 'estimated_time_value', 'scanned_files', 'scanned_files_value', 'threats', 'threats_value', 'progressbar_id',
                    'path_object'
            ]

            if scan_type == 'fullscan':
                widget_value = [
                    (0.555, 0.64), (0.63, 0.64), (0.53, 0.6), (0.665, 0.6), (0.77, 0.64), (0.83, 0.64), (0.772, 0.6), (0.83, 0.6), (0.475, 0.1), (0.68, 0.53)
                ]
                
            else:
                widget_value = [
                    (0.555, 0.37), (0.63, 0.37), (0.53, 0.33), (0.665, 0.33), (0.77, 0.37), (0.83, 0.37), (0.772, 0.33), (0.83, 0.33), (0.475, -0.18), (0.68, 0.25)
                ]
                    
            for prob_count,id_s in enumerate(progressbar_ids):
                x_value,y_value = widget_value[prob_count]
                self.ids[id_s].pos_hint = {'x':x_value , 'y':y_value }
            return
        
        # def header_label(self):
            
        #     """ This Method is to save the header state in database and maintain the states of duplicate license, Expire license , without license"""
            
        #     Method_ = ''    
        #     fetch_data = AU.db_management('select  File_Name from User_Action limit 1')         
        #     fetch_data = True if len(fetch_data)>=1 else False
            
        #     if fetch_data:
        #         if self.Licence_Activity and self.AV_OPTIONS['Header_Msg'] != 'duplicate_Licence_ids':
        #             pass
        #         elif self.AV_OPTIONS['Header_Msg'] == 'duplicate_Licence_ids':
        #             self.id_state_handler('duplicate_Licence_ids')
        #             Method_ = 'duplicate_Licence_ids'
        #         else:
        #             self.id_state_handler('duplicate_Licence_ids')
        #             Method_ = 'duplicate_Licence_ids'
                
        #         if type(GM.Auth_table_dict['remaining_days']) == int and self.Licence_Activity:
                    
        #             if self.AV_OPTIONS['Header_Msg'] == 'Without_Licence_ids':
        #                 Method_ = 'Without_Licence_ids'
        #             elif  self.AV_OPTIONS['Header_Msg'] == 'duplicate_Licence_ids':
        #                 pass
        #             else:
        #                 Method_ = 'Zero_remain_days'
        #         else:pass
                
        #         if type(GM.Auth_table_dict['remaining_days']) == int:
        #             Method_ = 'Zero_remain_days'
        #         else:pass
                    
        #     else:
        #         if type(GM.Auth_table_dict['remaining_days']) == int:
        #             self.id_state_handler('Zero_remain_days')
        #             Method_ = 'Zero_remain_days'
        #         else:
        #             self.id_state_handler('Without_Licence_ids')
        #             Method_ = 'Without_Licence_ids'
                    
        #     GM.auth_table_config()
        #     GM.initial_loads()
        #     AU.db_management("update Status_Master set Header_Msg = '"+Method_+"' ") if Method_ else ''

     
        #### THE BELOW METHOD IS HELPS CALCULATE PROGRESSBAR WIDGETS CALCULATION AND SCANNING
        def progressbar_widgets_scanning_calc(self,path,scan_type):
            
            """ 
            This Method is used to calculate progress bar values and progress bar value and send the calclated path to antivirus scanning mehtod
            and receive malicious file status threatname from it , it calculates the following values (self.estimated_time, current_time, duration. self.threat_count
            self.current_file_count, progress_value, scanned_files_value, path_object, estimated_time_value)
            """
            
            gc.collect()
            try:
                if self.scan_status:
                    self.ids['path_object'].text = f"[color=#08fcfc]Scan stopped...! {self.threat_count} files are {self.AV_OPTIONS['threat_action']}"
                    return
                else:pass
                
                self.current_file_count += 1 
                #### THE BELOW STATEMENT IS TO PERFORMING SCANNING 
                threat_name ,Ismalicious = ABac().antivirus_scanner(path)
                
                path_print = ''
                path_split = path.split('/')
                path_front = ('/'.join(x for x in path_split[:2]))
                path_print = f"{path_front}/..../{path_split[-1]}"
                path_print = path_print[:61]
                Scan_Path = None if scan_type == 'Full Scan' else self.browse_dirname

                print("GM.est_tm_calc.seconds",GM.est_tm_calc.seconds)
                sec = GM.est_tm_calc.seconds 
                sec = sec if sec and self.current_file_count != self.total_file_count else 1

                #### THE BELOW STATEMENT IS TO CALCULATE ESTMATED TIME AND DURATION 
                self.estimated_time = timedelta(seconds=((self.total_file_count - self.current_file_count)*sec))
                print("self.estimated_time",self.estimated_time)
                
                #### THE BELOW STATEMENT IS TO CALCULATE THREATS
                if threat_name:
                    self.threat_count += 1
                    self.ids['threats_value'].text = f"[color=#Fc1908]{self.threat_count}[/color]"

                elif self.threat_count == 0:
                    self.ids['threats_value'].text = f"[color=#33f3ef]No[/color]"
                else:
                    pass

                #### THE BELOW STATEMENT IS TO ENABLE PROGRESS BAR WIDGETS OPACITY
                if self.current_file_count == 1:
                    self.progress_bar_widgets_position('fullscan') if scan_type == 'Full Scan' else self.progress_bar_widgets_position('customscan')
                else: 
                    pass 
                
                #### THE BELOW STATEMENT IS TO CALCULATE AND ASSIGN ALL PROGRESS BAR WIDGETS ACCORDING TO FULL OR CUSTOM SCAN
                if self.current_file_count >= self.total_file_count:
                    self.ids['progress_value'].text = f"[color=#33f3ef]{round(((self.current_file_count/self.total_file_count)*100),2)}%" 
                    
                    self.ids['scanned_files_value'].text = f"[color=#33f3ef]{self.current_file_count}" 
                    self.ids['path_object'].text = f"[color=#08fcfc]{path_print}"
                    self.ids['path_object'].text = f"[color=#08fcfc]Scan Complete.....! {self.threat_count} files are {self.AV_OPTIONS['threat_action']}"
                    AU.db_management("insert into Scan_History (Date_Time,Scan_Type,Scan_Status,Scanned_Count,Threat_Count,Duration,Scan_Path)values(?,?,?,?,?,?,?);",tuple((self.started_time,scan_type,'C',self.current_file_count,self.threat_count,duration,Scan_Path)))

                elif self.scan_status:
                    self.ids['path_object'].text = f"[color=#08fcfc]Scan stopped...! {self.threat_count} files are {self.AV_OPTIONS['threat_action']}"
                    AU.db_management("insert into Scan_History (Date_Time,Scan_Type,Scan_Status,Scanned_Count,Threat_Count,Duration,Scan_Path)values(?,?,?,?,?,?,?);",tuple((self.started_time,scan_type,'S',self.current_file_count,self.threat_count,duration,Scan_Path)))
                
                else: 
                    self.ids['progressbar_id'].opacity=1
                    self.ids['progress_value'].text = f"[color=#dc7127]{round(((self.current_file_count/self.total_file_count)*100),2)}%" 
                    self.ids['scanned_files_value'].text = f"[color=#dc7127]{self.current_file_count}" 
                    self.ids['path_object'].text = f"[color=#08fcfc]{path_print}"

                if self.total_file_count == 1:
                    self.ids['estimated_time_value'].text = f"[color=#dc7127]{'00 sec'}[/color] / [color=#08fcfc]{'00 sec'}[/color]" 
                    time.sleep(2)
                else:pass

                return True

            except Exception as exception:
                print('progressbar_widgets_scanning_calc--->',exception)
                return False 
        
        #####THE BELOW METHOD IS TO MAINTAIN SCAN DURATION
        def scan_duration(self):
            cnt = 0
            while True:
                time.sleep(1)
                if self.scan_status:
                    self.ids['path_object'].text = f"[color=#F5F2F2]Scan stopped...! {self.threat_count} files are {self.AV_OPTIONS['threat_action']}"
                    self.id_state_handler('full_scan_empty_progressbar')
                    self.button_status(self.AV_WIDGETS_ACTION['custom_scan_stop'])
                    self.button_status(self.AV_WIDGETS_ACTION['stop_scan_dm_value'])
                    self.button_status(self.AV_WIDGETS_ACTION['full_scan_stop'])
                    self.ids['progressbar_id'].opacity=0.2
                    AU.show_notification("Scan Process Stopped.")
                    self.total_file_count = 0
                    break
                else:pass
                
                if int(self.AV_OPTIONS['full_scan']) or int(self.AV_OPTIONS['custom_scan']):pass
                else:break

                if self.total_file_count :
                    cnt+=1

                    if cnt == 1:
                        AU.show_notification("Scan Process Starts !!") 
                    else:pass

                    current_time = datetime.now()
                    duration = current_time-self.started_time
                    self.duration = str(duration).split('.')[0]
                    total_time = GM_instance.time_string_calculator(str(self.estimated_time).split(':'))
                    self.ids['estimated_time_value'].text = f"[color=#dc7127]{total_time}[/color] / [color=#08fcfc]{self.duration}[/color]" 
                    time.sleep(1)
                else:
                    if not self.scan_status:
                        self.ids['path_object'].text = f"[color=#F5F2F2]Processing Items {GM.file_cnt}"

        #### THE BELOW METHOD IS HELPS TO START FULL SCAN
        def full_scan(self):
            """
            Full scan Method is used to handle full scan operation such as button state, Full scan Thread, receive total file from path_spliter
            Method and sen to progressbar widgets method the control start and stop scans the path received from path_filter
            has seperated into maximum four partition then create a thread count based on that partition 
            """
            gc.collect()
            self.AV_OPTIONS['full_scan'] = '1'
            self.td_cont = 0
            AntivirusGUI.stop_scan_classmethod(False)
            AU.db_management("update Status_Master set Full_Scan = '"""+(self.AV_OPTIONS['full_scan'])+"""'""")
            
            #### THE BELOW STATEMENTS IS HELPS TO SET AND ALIGN PROGRESS WEDGET POSITIONS
            self.progress_bar_widgets_position('fullscan')
            self.id_state_handler('full_scan_startup_ids')

            
            logging.info("Full-Scan Process Started !!")

            self.button_status(self.AV_WIDGETS_ACTION['full_scan_startup'])
    
            #### THE BELOW METHOD IS FOR THEARDING
            def current():
                """ Full-scan Process Block Start """
                try:
                    self.started_time = datetime.now()

                    scan_dur_thread = Thread(target=self.scan_duration)
                    scan_dur_thread.name = "scan_dur_thread"
                    scan_dur_thread.start()
                    self.td_cont = 1
                    
                    def thread_maker(*file_path):
                        gc.collect()
                        for path in file_path:
                            if self.scan_status  or GM.licence_interrupt: 
                                # self.id_state_handler('duplicate_Licence_ids') if GM.licence_interrupt else ''        
                                break
                            else:
                                self.progressbar_widgets_scanning_calc(path,'Full Scan')
                                if not self.td_cont:
                                    pass
                                
                    def probarvalue():
                        while self.current_file_count<self.total_file_count:
                            if self.scan_status  or GM.licence_interrupt: 
                                # self.id_state_handler('duplicate_Licence_ids') if GM.licence_interrupt else ''        
                                break
                            time.sleep(0.5)
                            self.ids['progressbar_id'].value = self.current_file_count
    
                    hash_sep_val = GM.path_spliter('','full_scan')
                    
                    
                    self.total_file_count = len(hash_sep_val)
                    self.ids['progressbar_id'].max = self.total_file_count
                    
                    
                    if not self.scan_status:
                        if self.total_file_count == 1 and hash_sep_val[0].endswith('.ini') or not self.total_file_count:
                            self.button_status(self.AV_WIDGETS_ACTION['full_scan_exception']) 
                            AU.show_notification(f"Scan Stopped ! There is no files in that folder you selected")
                            self.id_state_handler('full_scan_empty_progressbar')
                            return
                        
                        elif self.total_file_count == 1:  
                            # AU.show_notification("Full-Scan Process Started !!")                        
                            thread_maker(hash_sep_val[0])  
                        
                        elif  self.total_file_count > 1:
                            
                            count = 4
                            Sp = self.total_file_count//4
                            hash_sep_val = [hash_sep_val[:Sp],hash_sep_val[Sp:Sp+Sp],hash_sep_val[Sp+Sp:Sp+Sp+Sp],hash_sep_val[Sp+Sp+Sp:]]
                            for c in range(1,count+1):
                                if self.scan_status  or GM.licence_interrupt: 
                                    # self.id_state_handler('duplicate_Licence_ids') if GM.licence_interrupt else ''        
                                    break
                                split_data = hash_sep_val[c-1]
                                Full_scanSub_Thread = Thread(target = thread_maker,args = (split_data) )
                                Full_scanSub_Thread.name = f"Full_scanSub_Thread {c}"
                                Full_scanSub_Thread.start()
                            
                            prothred = Thread(target = probarvalue)
                            prothred.name = 'progress bar thred'
                            prothred.start()
                            Full_scanSub_Thread.join()
                            prothred.join()
                            
                        else:
                            count = 1
                        if not self.scan_status:
                            AU.show_notification(f"Full-Scanning Process Completed.")
                            self.button_status(self.AV_WIDGETS_ACTION['full_scan_complete'])
                            self.id_state_handler('full_scan_empty_progressbar')
                        else:
                            self.id_state_handler('full_scan_empty_progressbar')
                            self.button_status(self.AV_WIDGETS_ACTION['stop_scan_dm_value'])
                            self.ids['progressbar_id'].opacity=0.2
                            self.ids['path_object'].text = f"[color=#08fcfc]Scan stopped...!  {self.threat_count} files are {self.AV_OPTIONS['threat_action']}"
                            AU.show_notification("FullScan Process Stopped.")
                            self.button_status(self.AV_WIDGETS_ACTION['full_scan_stop'])
                            
                    else:
                        self.id_state_handler('full_scan_empty_progressbar')
                        self.button_status(self.AV_WIDGETS_ACTION['stop_scan_dm_value'])
                        self.ids['progressbar_id'].opacity=0.2
                        self.ids['path_object'].text = f"[color=#08fcfc]Scan stopped...!  {self.threat_count} files are {self.AV_OPTIONS['threat_action']}"
                        AU.show_notification("FullScan Process Stopped.")
                        self.button_status(self.AV_WIDGETS_ACTION['full_scan_stop'])
                            
                except Exception as exe : 
                    AU.show_notification("FullScan Process Stopped.")
                    self.button_status(self.AV_WIDGETS_ACTION['full_scan_exception']) 

                finally:
                    self.last_scan()
                    self.AV_OPTIONS['full_scan'] = '0'
                    self.ids['progressbar_id'].value = 0
                    AU.db_management("update Status_Master set Full_Scan = '"""+(self.AV_OPTIONS['full_scan'])+"""'""")
                    # if GM.Auth_table_dict['remaining_days'] == 'Duplicate':
                    #     self.button_status(self.AV_WIDGETS_ACTION['license_notverified'])
                    # else:pass 
                    
            #### THE BELOW STATEMENTS IS HELPS TO START THREAD FOR FULL SCAN
            full_scan_thread = Thread(target = current,daemon = True)
            full_scan_thread.name = "Full_Scan_Thread"
            full_scan_thread.start()
            
            """ Full-scan Process Block End """ 
            return
            
        
        #### THE BELOW METHOD IS HELPS TO START CUSTOM SCAN  
        def custom_scan(self):
            """
            Custom scan Method is used to handle full scan operation such as button state, Full scan Thread, receive total file from path_spliter
            Method and sen to progressbar widgets method the control start and stop scans the path received from path_filter
            has seperated into maximum four partition then create a thread count based on that partition.
            """
            gc.collect()
            self.td_cont = 0
            self.AV_OPTIONS['custom_scan'] = '1'
            AntivirusGUI.stop_scan_classmethod(False)
            AU.db_management("update Status_Master set Custom_Scan = '"""+(self.AV_OPTIONS['custom_scan'])+"""'""")

            #### THE BELOW STATEMENTS IS HELPS TO CHECK FILE OR FOLDER FOR BROWSE PATH
            if self.browse_option == 'File':
                file_folder_hide ='file_box_tick'
            else:
                file_folder_hide ='folder_box_tick'

            ### function for  start custom scan 
            def current():
                """ custom-scan Process Block Start """
                try:
                    if self.browse_dirname != "":
                        hash_dict = {}
                        self.button_status(self.AV_WIDGETS_ACTION['custom_scan_startup']) 
                        self.progress_bar_widgets_position('customscan')
                    
                        self.id_state_handler('custom_scan_startup_ids')

                        custom_scanPath = self.browse_dirname   
                        logging.info(f"Custom-scanPath : {custom_scanPath}")
                        # logging.info(f"Custom-Scan Process Started !!")
                        
                        self.started_time = datetime.now()
                        
                        def thread_maker(*file_path):
                            gc.collect()
                            for path in file_path:
                                if self.scan_status  or GM.licence_interrupt: 
                                    # self.id_state_handler('duplicate_Licence_ids') if GM.licence_interrupt else ''        
                                    break
                                else:
                                    self.progressbar_widgets_scanning_calc(path,'Custom Scan')
                                    if not self.td_cont:
                                        scan_dur_thread = Thread(target=self.scan_duration)
                                        scan_dur_thread.name = "scan_dur_thread"
                                        scan_dur_thread.start()
                                        self.td_cont = 1

                        def probarvalue():
                            while self.current_file_count<self.total_file_count:
                                if self.scan_status  or GM.licence_interrupt: 
                                    # self.id_state_handler('duplicate_Licence_ids') if GM.licence_interrupt else ''        
                                    break
                                time.sleep(0.5)
                                self.ids['progressbar_id'].value = self.current_file_count
                            
                        if os.path.exists(custom_scanPath):
                            hash_sep_val = GM.path_spliter(custom_scanPath,'custom_scan')
                            
                        else:
                            AU.show_notification("Invalid file path Please select the valid path")
                            self.scan_status = True

                        if not self.scan_status:       
                            self.total_file_count = len(hash_sep_val)   
                            # self.estimated_time = timedelta(seconds=self.total_file_count*1)
                            self.ids['progressbar_id'].max = self.total_file_count
                            count=0
                            
                            if self.total_file_count == 1 and hash_sep_val[0].endswith('.ini') or not self.total_file_count :
                                time.sleep(2)
                                AU.show_notification("Scan Stopped ! There is no files in that folder you selected")
                                time.sleep(1)
                                self.AV_WIDGETS_ACTION['custom_scan_stop']['enable'].append(file_folder_hide)
                                self.button_status(self.AV_WIDGETS_ACTION['custom_scan_stop'])
                                self.AV_WIDGETS_ACTION['custom_scan_stop']['enable'].pop()
                                return
                            
                            elif self.total_file_count == 1: 
                                AU.show_notification("Custom-Scan Process Started !!") 
                                time.sleep(1)                        
                                thread_maker(hash_sep_val[0])
                                # AU.show_notification("Custom-Scan Process Started !!") 
                                
                            elif  self.total_file_count > 1:
                                AU.show_notification("Custom-Scan Process Started !!")
                                time.sleep(1)
                                count = 4
                                Sp = self.total_file_count//4
                                hash_sep_val = [hash_sep_val[:Sp],hash_sep_val[Sp:Sp+Sp],hash_sep_val[Sp+Sp:Sp+Sp+Sp],hash_sep_val[Sp+Sp+Sp :]]
                                
                                for c in range(1,count+1):
                                    if self.scan_status  or GM.licence_interrupt: 
                                        # self.id_state_handler('duplicate_Licence_ids') if GM.licence_interrupt else ''        
                                        break
                                    split_data = hash_sep_val[c-1]
                                    Custom_scanSub_Thread = Thread(target = thread_maker,args = (split_data) )
                                    Custom_scanSub_Thread.name = f"Custom_scanSub_Thread {c}"
                                    Custom_scanSub_Thread.start()
                                    
                                prothred = Thread(target = probarvalue)
                                prothred.name = 'prothred'
                                prothred.start()
                                # AU.show_notification("Custom-Scan Process Started !!")
                                Custom_scanSub_Thread.join()
                                prothred.join()
                                
                            else:
                                count = 1
                            if not self.scan_status:
                                AU.show_notification(f"Custom-Scan Process Completed.")
                                self.AV_WIDGETS_ACTION['custom_scan_complete']['enable'].append(file_folder_hide)
                                self.button_status(self.AV_WIDGETS_ACTION['custom_scan_complete'])
                                self.AV_WIDGETS_ACTION['custom_scan_complete']['enable'].pop()
                                
                            else:
                                AU.show_notification("Custom-Scan Process Stopped.")
                                self.AV_WIDGETS_ACTION['custom_scan_stop']['enable'].append(file_folder_hide)
                                self.button_status(self.AV_WIDGETS_ACTION['custom_scan_stop'])
                                self.AV_WIDGETS_ACTION['custom_scan_stop']['enable'].pop()
                        else:
                            AU.show_notification("Custom-Scan Process Stopped.")
                            self.AV_WIDGETS_ACTION['custom_scan_stop']['enable'].append(file_folder_hide)
                            self.button_status(self.AV_WIDGETS_ACTION['custom_scan_stop'])
                            self.AV_WIDGETS_ACTION['custom_scan_stop']['enable'].pop()
                    else:
                        AU.show_notification(f"Please Give your Valid Custom-Scan Path.")
                        self.AV_WIDGETS_ACTION['custom_scan_empty_string']['enable'].append(file_folder_hide)
                        self.button_status(self.AV_WIDGETS_ACTION['custom_scan_empty_string'])
                        self.AV_WIDGETS_ACTION['custom_scan_empty_string']['enable'].pop()
                        
                except Exception as exe:
                    print(f"Custom Scan {exe}")
                    AU.show_notification("Custom-Scan Process Stopped.")
                    self.AV_WIDGETS_ACTION['custom_scan_empty_exception']['enable'].append(file_folder_hide)
                    self.button_status(self.AV_WIDGETS_ACTION['custom_scan_empty_exception'])
                    self.AV_WIDGETS_ACTION['custom_scan_empty_exception']['enable'].pop()

                finally:
                    self.last_scan()
                    self.AV_OPTIONS['custom_scan'] = '0'
                    self.ids['progressbar_id'].value = 0
                    AU.db_management("update Status_Master set Custom_Scan = '"""+(self.AV_OPTIONS['custom_scan'])+"""'""")
                    # if GM.Auth_table_dict['remaining_days'] == 'Duplicate':
                    #     self.button_status(self.AV_WIDGETS_ACTION['license_notverified'])
                    # else:pass

            #### THE BELOW STATEMENTS IS HELPS TO START THREAD FOR CUSTOM SCAN 
            custom_scan_thread = Thread(target = current,daemon = True)
            custom_scan_thread.name = "Custom_Scan_Thread"
            custom_scan_thread.start()   
                
            '''  Custom-scan Process Block End '''
            return

        #### THE BELOW class METHOD IS FOR STOP FULLSCAN AND CUSTOM STOP BUTTON
        @classmethod
        def stop_scan_classmethod(cls,status):
            """ The Method is terminate  full scan and custom scan process"""
            GM.scan_status = True
            cls.scan_status = status

        #### THE BELOW METHOD IS FOR LOG DOWNLOADER EITHER CSV OR TEXT
        def log_downloader(self,file_type):
            
            """ 
            log_downloader Method create a text file while we press download button in History option
            it takes the rows from database and process the text then write into text file 
            it can also create a csv file if Method parameter is csv
            """

            date_ = self.from_date.strftime("%d%b%Y")
            from_date = datetime.strftime(self.from_date,"%Y-%m-%d")
            to_date = ""

            if self.from_date != self.to_date:
                date_ = self.from_date.strftime("%d%b%Y")+'_'+self.to_date.strftime("%d%b%Y")
                to_date = datetime.strftime(self.to_date,"%Y-%m-%d")
            logfile_name = self.downloads_dir+'/'+'AV_LOG_'+date_

            Log_Data = AU.db_management("""
                select SUBSTR(a.Date_Time, 1, 19) date,CASE when Malicious = '0' then '"Harmless File"' else '"Malicious File  '||Threat_name||'"' end Threat ,Source_Path
                from User_Action a
                left join Offline_Master b on a.Hash_ID = b.id
                WHERE a.Date_Time >= '"""+from_date+"""' or a.Date_Time <= '"""+to_date+"""' ORDER by a.Date_Time
            """
            )
    
            txtFname = logfile_name+'.txt'
            open(txtFname,mode = 'w').close()
            # row_count = 0

            for raw_line in Log_Data:
                # row_count += 1
                file_open = open(txtFname,mode = 'a')
                write_data = ' '.join(i.replace(',','   ')if ',' in i else i for i in raw_line)
                file_open.write(f"  {write_data}\n")
                file_open.close()

            # #### THE BELOW IF ELSE FOR CHECKING IF DATA IS THERE IT WILL SAVE OR REMOVE THE FILE 
            if Log_Data:
                self.button_status({
                    'enable':[
                        'file_downloadicon_button'
                    ]
                })
                self.ids['download_icon_label'].text = '[b][color=#33f3ef]LOG File Downloaded......![/b]'
                self.ids['download_icon_label'].color = (0,1,1,1)
                AU.show_notification(f"{AV_TITLE} Log File Downloaded......!")
            
            else:   
                try:           
                    os.remove(logfile_name+'.txt')
                    os.remove(logfile_name+'.csv')
                except:
                    pass
                self.ids['download_icon_label'].text = '[b][color=#FF0000]No Data ( File Not Downloaded......! )[/b]'
                self.ids['download_icon_label'].color = (1, 99/255, 71/255,1)
                AU.show_notification("No Data ( File Not Downloaded......! )")
            '''Log file function Ends '''
            return

        #### THE BELOW METHOD TO VIEW AND OPEN THE DOWNLOAD TEXT OR CSV FILE 
        def download_file_view(self): 
            
            """
            download_file_view is helps to open the downloaded log file from history 
            """   
            def file_open(file_name):
                try:
                    file_name = file_name[0]
                    if sys.platform == "win32":
                        os.startfile(file_name)
                    else:
                        opener = "open" if sys.platform == "darwin" else "xdg-open"
                        subprocess.call([opener, file_name])
                except:
                    pass
                return
            #### THE BELOW STATEMENT IS FOR SELECTING DOWNLOAD FOLDER PATH
            try:
                downloads_dir = os.path.join(Path.home(),'Downloads')
                filechooser.open_file(title="AntiVirus Report Downloaded files",path=downloads_dir,filters=[("test files", "*.txt")],on_selection=file_open)
            except:
                pass
            return
        
        ####  THE BELOW METHOD IS FOR ENABLE AND DISABLE THE BUTTON STATUS
        def button_status(self,id_list):
            """ button_status function is to handle all the button status which i have used in This application"""
            for key in id_list.keys():  
                for id in id_list[key]:
                    try:
                        if key == 'enable':
                            self.ids[id].opacity = 1
                            self.ids[id].color = 1,1,1,1
                            self.ids[id].disabled = False 
                        elif key == 'empty':
                            self.ids[id].text = ''
                        elif key == 'hide':
                            self.ids[id].color = 0,0,0,0
                            self.ids[id].opacity = 0
                        elif key == 'hide_disable':
                            self.ids[id].opacity = 0
                            self.ids[id].color = 0,0,0,0
                            self.ids[id].disabled = True
                        elif key == 'Q_dis':
                            self.ids[id].opacity = 1
                        elif key == 'Q_hid':
                            self.ids[id].opacity = 0
                        else:
                            self.ids[id].opacity = 0.5   
                            self.ids[id].disabled = True
                            self.ids[id].color = 0,0,0,0.5
                    except:
                        pass
            
                        
            return
    
    ####  THE BELOW METHOD IS FOR ENABLE AND DISABLE THE BUTTON STATUS 
    class AntivirusSoftware(MDApp):
        """ This is the app builder for this GUI """
        def build(self):
            self.icon = f"{dir_path}static/images/BRAND_ICON.png"
            self.title = 'Dima Antivirus'
            AV = AntivirusGUI()
            return AV

        def on_start(self, **kwargs):
            """ This method will execute while GUI starts"""
            time.sleep(1)
            if sys.argv[-1] == 'from_startup':
                if type(GM.Auth_table_dict['remaining_days']) == int :
                    pass
                else:
                    Window.show()
                    Window.show() 
            else:
                Window.show()
                Window.show()
    
    if __name__ == "__main__":
        try:    
            AntivirusSoftware().run()
        except Exception as ex:
            logging.exception(f"ERROR-MESSAGE")
            
except Exception as ese:                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  
    print('Main_thread-----',ese)
    subprocess.Popen([f'{dir_path}/UR_Pro_Handler.exe', 'AV_Rollback'])
    sys.exit()
