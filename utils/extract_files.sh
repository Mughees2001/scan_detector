#!/bin/bash

FILES=`find . -name "*.pcap" -exec echo {} \;`

for FILE in $FILES
do
    MOD_FILE=`echo $FILE | sed 's/\//\_/g'`
    echo $FILE
    echo $MOD_FILE
    cp $FILE tmp/$MOD_FILE
    tshark -r /tmp/$MOD_FILE/
done
