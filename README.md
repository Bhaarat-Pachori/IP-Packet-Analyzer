# IP-Packet-Analyzer
This source code is a working IP packet packet analyzer, that can analyze the given IP packets. For now, the packets (xxx.bin) in data folder are trimmed a bit to suit the requirement. Although, the code will work for any packet.

Steps to evaluate the results:

1. Use this command to read the .bin files 
xxd -ps icmp.bin 
c0143dd5728b001da1385800080045000028d4310000f40105a2c6146382
81154255080060b1974e0000000000000000000000000000000000000000

2. Now paste this output to the the window on left to verify the results.
https://www.gasmi.net/hpd/
and press "Decode the Packet" button at the bottom of the window.
