
# simple multi-tool by @antidepressants
# telegram: @antidepressants
# icq: @antidepressants

import requests
import hashlib
import json
import os


logo = '''
           _   _         _            _ 
  __ _ _ _| |_(_)  ___  | |_ ___  ___| |
 / _` | ' \  _| | |___| |  _/ _ \/ _ \ |
 \__,_|_||_\__|_|        \__\___/\___/_|

  Made by @antidepressants on telegram!
                                    '''

helps ='''

╔═══════════════╦══════════════════════════╗
║   commands    ║       description        ║
╠═══════════════╬══════════════════════════╣
║ help          ║ shows a list of commands ║
║ geoip         ║ shows geographical info  ║
║ hash          ║ simple hash tools        ║
║ emailsearch   ║ database leak search     ║
║ pinger        ║ pings an ip address      ║
║ proxydetector ║ checks for a proxy       ║
║ wafchecker    ║ checks for l7 security   ║
║ skyperesolver ║ resolves usernames       ║
║ pscanner      ║ host port scanner        ║
╚═══════════════╩══════════════════════════╝
 '''

comm = ["help","geoip","hash","emailsearch","pinger","proxydetector","wafchecker","skyperesolver","pscanner"]

def geoip():
    geoip = input("[X] Enter the host:")
    url = "https://api.hackertarget.com/geoip/?q=" + geoip + ""
    r = requests.get(url)
    print("[X] Results: " + r.text)

def pscanner():
    port = input("[X] Enter the host:")
    url = "https://api.c99.nl/portscanner?key=pick0363r80@hotmail.fr&host=" + port +""
    r = requests.get(url)
    print("[X] Results: " + r.text)

def hash():
    text = input("[*] Enter string: ")
    types = input("[*] md5,sha256,sha1,sha224,sha384,sha512: ")
    if types == "md5":
        hash_object = hashlib.md5(text.encode())
        print("[!] Hashed string: " + hash_object.hexdigest())
    if types == "sha1":
        hash_object = hashlib.sha1(text.encode())
        print("[!] Hashed string: " + hash_object.hexdigest())
    if types == "sha224":
        hash_object = hashlib.sha224(text.encode())
        print("[!] Hashed string: " + hash_object.hexdigest())
    if types == "sha256":
        hash_object = hashlib.sha256(text.encode())
        print("[!] Hashed string: " + hash_object.hexdigest())
    if types == "sha384":
        hash_object = hashlib.sha384(text.encode())
        print("[!] Hashed string: " + hash_object.hexdigest())
    if types == "sha512":
        hash_object = hashlib.sha512(text.encode())
        print(hash_object.hexdigest())

def proxydetector():
    proxy = input("[X] Enter host:")
    url = "https://api.c99.nl/proxydetector?key=pick0363r80@hotmail.fr&ip=" + proxy + ""
    r = requests.get(url)
    print("[X] Results: " + r.text)

def skyperesolver():
    skype = input("[X] Enter username:")
    url = "https://api.c99.nl/skyperesolver?key=pick0363r80@hotmail.fr&username=" + skype +""
    r = requests.get(url)
    print("[X] Results: " + r.text)

def pinger():
    ip = input("[*] Enter ip: ")
    os.system("ping -n 4 {}".format(ip))

def weleak():
    com = input("[X] Enter email:")
    url = "https://api.weleakinfo.to/api?value=" + com + "&type=email&key=IPLH-OQGD-IFOA-MVAY"
    response = requests.get(url)
    data = response.text
    parsed = json.loads(data)
    print(json.dumps(parsed, indent=4))

def wafchecker():
    waf = input("[X] Enter host:")
    url = "https://api.c99.nl/firewalldetector?key=pick0363r80@hotmail.fr&url=" + waf +""
    r = requests.get(url)
    print("[X] Results: " + r.text)

def whois():
    whois = input("[X] Enter host:")
    url = "https://api.c99.nl/whois?key=pick0363r80@hotmail.fr&domain=" + whois + ""
    r = requests.get(url)
    print("[X] Results: " + r.text)

def resolver():
    resolver = input("[X] Enter host:")
    url = "https://api.c99.nl/subdomainfinder?key=pick0363r80@hotmail.fr&domain=" + resolver + ""
    r = requests.get(url)
    print("[X] Results: " + r.text)

def commands():
    com = input("[X] ")
    while com not in comm:
        com = input("[X] ")
    if com == "help":
        print(helps)
    elif com == "geoip":
        geoip()
    elif com == "hash":
        hash()
    elif com == "emailsearch":
        weleak()
    elif com == "pinger":
        pinger()
    elif com == "proxydetector":
        proxydetector()
    elif com == "wafchecker":
        wafchecker()
    elif com == "skyperesolver":
        skyperesolver()
    elif com == "pscanner":
        pscanner()
  
print(logo)
while True:
    commands()
