#!/bin/bash
if [ "$2" = "" ]
then
	echo "Scanner"
	echo "Usage: $0 interval interface [loop=true/false]"
        exit
fi

interval=$1
interface=$2
if [ "$3" = "true" ]; then
	loop=true;
else
	loop=false;
fi

echo "Configuring wlan1 ..."
ifconfig $interface down
iwconfig $interface mode monitor
ifconfig $interface up
echo "Should be done!"

#echo "TCP-dump start..."
tcpdump -i $interface -w packets2.cap &

channel=1
doWhile=true
while $doWhile
do
	echo "Current channel: $channel"
	iwconfig $interface channel "$channel"
	let "channel += 1"
	sleep $interval
	if (( $channel == 14 )); then
		channel=1;
		doWhile=loop;
	fi
done

echo "Results"
python /root/lan/analyse.py -i packets2.cap

