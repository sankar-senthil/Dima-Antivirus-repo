import requests
path = r"C:\Users\Sankar_Senthil\Downloads\urls.csv"
usr = "sankarsenthil.17"
pas = "sankarsenthil28072021"
ip = "10.10.10.203"
port = "3128"

data = open(path,'r').readlines()
CERT = r"D:\Dima_Antivirus\DimaAV_InternetSecurity\WINDOWS-BUILD\AV_BUILD\DimaAV_Build\EXE_JSON_FR_SPEC\proxyCA.pem"
proxies = {'http': f'http://{usr}:{pas}@{ip}:{port}','https':f'http://{usr}:{pas}@{ip}:{port}',}

for i in data:
    try:
        response = response = requests.request("GET", f" http://{i.strip()}", headers=[], data=[] , proxies=proxies, verify = CERT)      
        if response.status_code not in [200,201]:
            print(i.strip())
            open("block.txt",'a').write(i.strip()+'\n')
    except Exception as ese:
        print(ese)
        
    