#!/bin/bash

while read line
do
	STRIPPED_URL=$(echo $line | tr -dc "[:alnum:]")
	whatweb --log-json=$(pwd)/scan_output/$STRIPPED_URL.json --log-error=$(pwd)/scan_output/$STRIPPED_URL.json --plugins +Parked-Domain $line
done < urls.txt