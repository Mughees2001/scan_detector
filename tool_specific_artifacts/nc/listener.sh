#!/bin/bash

#Make Sure Script Is Ran As Root
if [ $(id -u) != 0 ]; then
    echo; echo -e "\e[1;31mScript must be run as sudo. Please Type \"sudo\" To Run As Root \e[0m"; echo    
exit 1
fi

while true;
do
    nc -l -p $1
done
exit 0