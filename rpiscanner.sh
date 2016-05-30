#!/bin/bash
if [ "$2" = "" ]
then
	echo "Scanner"
	echo "Usage: $0 interface interval [loop=true/false]"
	echo "	interval - wlan = time per channel "
	echo "	           eth = scan time "
        exit
fi

interface=$1
interval=$2

if [ "$3" = "true" ]; then
	loop=true;
else
	loop=false;
fi
	
echo "Configuring $interface ..."
if [[ $interface = *"wlan"* ]]; then
	ifconfig $interface down
	iwconfig $interface mode monitor
	ifconfig $interface up
		echo "Should be done!"

elif [[ $interface = *"eth"* ]]; then
	ifconfig $interface down
	ifconfig $interface up
	ifconfig $interface promisc
	echo "Should be done!"
else
	echo "Not done!"
	exit
fi

tcpdump -i $interface -w packets_$interface.pcap &

if [[ $interface = *"wlan"* ]]; then
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
			doWhile=$loop;
		fi
		echo "-----------------"
		echo "Known AP stations"
		python /root/lan/wifi_analyse.py -i packets_$interface.pcap &
		echo "-----------------"
	done
else
	sleep $interval
fi
ifconfig $interface down
ifconfig $interface up

if [[ "$interface" = *"wlan"* ]]; then
	python /root/lan/PcapViz/main.py -i /root/lan/packets_$interface.pcap -o /root/lan/topology_$interface.png --dot11 &
else
	python /root/lan/PcapViz/main.py -i /root/lan/packets_$interface.pcap -o /root/lan//topology_$interface.png --layer2 &
fi
