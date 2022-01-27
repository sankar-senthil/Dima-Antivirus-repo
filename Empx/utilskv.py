
__authors__ = "sankar senthil"
__copyright__ = "Copyright 2020, dimabusiness.com"
__version__ = "v2.3"
__maintainer__ = "sankar senthil"
__status__ = "Production"

import gc
import shutil
import os
import time

os.environ["KIVY_NO_FILELOG"] = "1"
os.environ["KIVY_NO_CONSOLELOG"] = "1"
from kivy.core.window import Window
from kivymd.uix.behaviors import HoverBehavior
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.factory import Factory
from kivy.uix.boxlayout  import BoxLayout
from kivy.properties import StringProperty
from datetime import datetime
from threading import Thread
from Empx.utils import AntivirusUtility, GeneralMethods, ApiLinks

class HovBtn(Button,HoverBehavior):
    """
    This class is to maintain hover button behavior the class created with the 
    combination of button and Hover behavior
    """
    def on_enter(self, *args):
        Window.set_system_cursor('hand')

    def on_leave(self, *args):
        Window.set_system_cursor('arrow')
        
        
class Hovtext(TextInput,HoverBehavior):
    """
    This class is to maintain hover Textinput behavior the class created with the 
    combination of Textinput and Hover behavior
    """
    def on_enter(self, *args):
        Window.set_system_cursor('ibeam')

    def on_leave(self, *args):
        Window.set_system_cursor('arrow')
        
class Action_popup(Popup):
    """ This is a popup class for Quarantine popup it handles all the Operations that happaning in the Quarantine Popup """
    
    thread_kill = False
    def __init__(self,**kwargs):
        gc.collect()
        global pagination_data
        self.Quarantine_thread = Thread(target = self.Quarantine_Path)
        self.Quarantine_thread.name = "Quarantine_thread"
        self.Quarantine_thread.start()
        super(Action_popup, self).__init__(**kwargs)

    def on_dismiss(self):
        """ iit Only executes when popup get dismissed """
        self.clear_widgets()
        self.remove_widget(self)
        
    def Quarantine_Path(self):
        """ This Method is Helps to display a Quarantine Path in Quarantine popup """
        global pagination_data
        pre_data = ''
        try:
            while True:
                if self.thread_kill:
                    GeneralMethods.popup_object_data.dismiss(force=True,animation = False)
                    Factory.Action_popup.thread_kill = False
                    break
                
                time.sleep(0.2)
                path = Factory.Table.tooltip_data
                if pre_data != path:
                    pre_data = path
                    path = f"{path[:71]}....." if len(path)>90 else path
                    self.ids['virus_pathinput'].text = path
                else:
                    pass
        except Exception as exe :
            print('Quarantine_Path',exe)   
            
class OTP_TXTInput(TextInput,HoverBehavior):
    """ It handles OTP Text input Block while giving licence """
    def insert_text(self, substring, from_undo=False):
        gc.collect()
        if len(self.text)>3:
            substring = ""
        test = [i for i in self.text if i.isalpha()]
        if len(test)>=1:
            substring, self.text = "", ""
        TextInput.insert_text(self, substring, from_undo)
        
    def on_enter(self, *args):
        Window.set_system_cursor('ibeam')

    def on_leave(self, *args):
        Window.set_system_cursor('arrow')
        
class OTP_popup(Popup):
    """ OTP Popup handles all the functions in the Quarantine  Popup screen"""
    def __init__(self,**kwargs):
        super(OTP_popup, self).__init__(**kwargs)
        gc.collect()
        self.sec = 120
        self.OTP_Sec_fn()
        time.sleep(1)
        AntivirusUtility.show_notification("OTP Successfully sent to your Registered Email-ID")
        
    def OTP_Sec_fn(self):
        """ The Method shows seconds and resend otp label"""
        self.ids['resend_otp_btn'].disabled = True
        def current():
            self.sec = 120
            while self.sec>=0:
                time.sleep(1)
                self.ids['resend_otp_btn'].text = f"[color=#51ff0d]{self.sec} s"
                self.sec-=1
            else:
                self.ids['resend_otp_btn'].disabled = False
                self.ids['resend_otp_btn'].text ='[color=#51ff0d][u]Resend OTP'
                self.sec = 120
        OTP_SEC_Thread = Thread(target =current)
        OTP_SEC_Thread.name = "OTP_SEC_Thread"
        OTP_SEC_Thread.start()
    def on_dismiss(self):
        self.sec = 0
        GeneralMethods.Lic_tuple = ''


 ####  THE BLEOW CLASS IS TO CREATE ROWS FOR ACTION POPUP
class Action_scrollview_Row(BoxLayout):
    """ The class creates a textinput boxes and buttons in Quarantine Scroll view page """
    global tooltip_dict
    txt = StringProperty()
    
    def __init__(self, row = '', **kwargs):
        self.clear_widgets()
        self.remove_widget(self)
        gc.collect()
        super(Action_scrollview_Row, self).__init__(**kwargs)
        self.txt1, self.txt2, self.txt3 = row[0], row[1], row[2]
        
        
    #### THE BELOW TABLE CLASS IS USED TO GENERATE SCROLL VIEW FOR QUARANTINED ITEMS IN ACTION POPUP        
class Table(BoxLayout):
    """ It handles all the operation inside the container"""
    gc.collect()
    global tooltip_dict, pagination_index, pagination_data,check_data
    check_data, tooltip_op_status, pagination_status = True, True, True
    tooltip_data, object_data, file_name = '', '', ''
    pagination_index, page_clsvar, Encry_Count = 0, 0, 0
    POPUP_CLOSE = False
    
    Query = """
            select a.id,a.Date_Time,File_Name,Source_Path,Hash_ID,Threat_Name from user_Action a
            left join Offline_Master b on a.Hash_ID = b.id
            WHERE Malicious = '1'and Action is NULL order by a.date_time desc
            """

    def __init__(self, **kwargs):
        gc.collect()   
        self.clear_widgets()
        self.remove_widget(self)
        super(Table, self).__init__(**kwargs)
        global tooltip_dict,Virus_status,pagination_data,pagination_index,check_data
        check_data = False
        if self.pagination_status :
            Widget_ROWS = AntivirusUtility.db_management(self.Query)
            if not Widget_ROWS:
                Virus_status = "No Virus Data"
                pagination_data = []
            else:
                Factory.Table.tooltip_data = ' '
                id = 0
                Virus_status = ''
                tooltip_dict, pagination_data = {}, []

            #### FOR LOOP HELPS TO ADD ROW WIDGETS IN THE SCROLL VIEW OF ACTION POPUP
                for row in Widget_ROWS:
                    try:
                        id +=1
                        date_format = datetime.strptime(row[1].split('.')[0],"%Y-%m-%d %H:%M:%S") 
                        row_2 = row[-1][:21]+"...."if len(row[-1])>=20 else row[-1] 
                        format_ = f"{id}|{row_2}|{datetime.strftime(date_format,'%b %d, %Y %I:%M %p')}"
                        tooltip_dict[format_] = row
                        pagination_data.append(format_)
                    except:pass
                    
        
        if pagination_index < 0 :
            pagination_index = 0
        elif pagination_index>len(pagination_data):
            pagination_index -= 10
        elif len(pagination_data) == pagination_index:
            if len(pagination_data) > 0 and pagination_index > 0:
                pagination_index -= 10
            else:
                pass
        elif not pagination_data:
            pagination_index = 0
        else:
            pass
            
        start_value = pagination_index
        if not pagination_data:
            pagination_index = 0
        else:
            pagination_index+=10
        end_value = pagination_index
        end_value = pagination_index
        self.pagination_status = True
        for table_data in pagination_data[start_value:end_value]:
            self.add_widget(Action_scrollview_Row(table_data.split('|')))
        check_data = True
        
    @classmethod
    def pagination_num_value_maintainer(cls,pro = ''):
        """ This function is to maintain the pagination index """
        
        global pagination_index, pagination_data, check_data
        if pro == 'clean':
            pagination_index = 0
            cls.Total_Files()
        elif pro == 'index_data':
            cls.page_clsvar = pagination_index
            if len(pagination_data) - (pagination_index-10) < 10 :
                final_data = (len(pagination_data)%10)+(pagination_index-10)

                if not pagination_index:
                    final_data = '0 - 0'
                else:
                    final_data = f"{cls.page_clsvar-9} - {final_data} "   
            else:
                if not pagination_index:
                    final_data = '0 - 0'
                else:
                    final_data = f"{cls.page_clsvar-9} - {cls.page_clsvar} "   
            cls.tooltip_op_status = check_data
            return str(final_data)

        else:
            pagination_index -= 20
        cls.tooltip_op_status = check_data

    @classmethod
    def Total_Files(cls):
        """ This function is to get total quarantine files  """
        cls.Encry_Count = AntivirusUtility.db_management("""
                select count(b.id) from Offline_Master a
                left join User_Action b on a.id = b.Hash_ID where Malicious = 1 and Action is NULL and Ignore_Action is NULL
        """)[-1][-1]
        return str(cls.Encry_Count)

    @classmethod
    def pop_element(cls,data):
        """ The Method is to pop the element from tooltip_dict"""
        global pagination_index, pagination_data, tooltip_dict
        try:
            global tooltip_dict
            db_data = tooltip_dict[data]
            file_loc =  db_data[3].split(db_data[2])[0]
            if os.path.exists(file_loc) or os.path.exists(db_data[3]):
                pagination_data.remove(data)
                tooltip_dict.pop(data)
            else:pass
        except:
            pass

    @classmethod
    def Delete_All(cls):
        """ This method is helps to delete all the files in Dima_Vault"""
        try:
            AntivirusUtility.db_management(
                "update User_Action set Action = 'Delete' where hash_id in (select id from Offline_Master where Malicious = 1) and Action is NULL "
            )
            DimaVault_path = f"{GeneralMethods.dir_path}\\Dima_Vault"
            shutil.rmtree(DimaVault_path)
            os.mkdir(DimaVault_path)
        except Exception as Exe:
            print('Delete_All--->',Exe)
    
    #### THE BELOW CLASS METHOD IS HELPS TO HANDLE TOOLTIP CURSOR AND DATA
    @classmethod
    def Action_Tooltip(cls,filename):
        """ This function handles tooltip operation """
        global tooltip_dict
        try:
            if tooltip_dict[filename][3]:
                return tooltip_dict[filename][3]
            else:
                return
        except Exception as e:
            print('Action_Tooltip-->',e)
            return ''
    
    #### THE BELOW CLASS METHOD IS HELPS TO ON AND OFF TOOLTIP BASED ON THE VARIABLE
    @classmethod
    def Virus_status_fun(cls):
        """ This method just return virus status """
        global Virus_status
        return Virus_status
    
    #### THE BELOW CLASS METHOD IS HELPS TO HANDLE RESTORE DELETE AND EXCEPT BUTTON FUNCTIONALITIES 
    @classmethod        
    def Button_Handler(cls,file_name,Button_Type):
        """ This method handles the restore, delete and ignore buttons """
        try:
            global tooltip_dict
            db_data = tooltip_dict[file_name]
            file_loc =  db_data[3].split(db_data[2])[0]
            
            if os.path.exists(file_loc) or os.path.exists(db_data[3]):
                AntivirusUtility().encryped_file_handler(db_data,Button_Type)
            else:
                AntivirusUtility.show_notification(f"No such file or directory: ' {tooltip_dict[file_name][3]} '")
                time.sleep(2)
                Factory.Table.tooltip_data = f"No such file or directory: ' {tooltip_dict[file_name][3]} '"
                pass
        except:
            pass


