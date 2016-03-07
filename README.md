# rogueap
Start a rogue access point with no effort, with support for hostapd, airbase, sslstrip, sslsplit, tcpdump builtin

Please keep in mind that tools that manage network connection (eg: ubuntun network-manager) can interfere with the workings of this tool


Example usages:

display all command line options
./rogueap --help

Create an simple access point that produces a pcap file
./rogueap --ssid "My wifi" wlan0 eth0

Create an acces point that reacts to all probes strips https traffic and playsm MitM for SSL/TLS connections on chanel 14, and log all to ~/log
./rogueap --channel 14 --sslstrip --sslsplit --logdir ~/log





