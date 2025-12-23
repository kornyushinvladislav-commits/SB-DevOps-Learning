#! /bin/bash

echo "Hello, $USER!"

SERVEROVPNDIR="/etc/openvpn/server/"
LOGFILENAME="/home/fquest/log/fquest.log"
SERVERCONFFILENAME="${SERVEROVPNDIR}server.conf"
DATE_TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

echo "'$DATE_TIMESTAMP' : start ConfiguringFirewall ()" >> "$LOGFILENAME"
sudo mkdir /home/$USER/log 2>> "$LOGFILENAME"

#echo "S - server C - client"
#read -p "Where will we work?  " where_wrk

#============================================================================================================
#============================================================================================================
#if [ "$where_wrk== "S" ]; then
#   echo "S will be selected"
#else   
#   echo "C will be selected"
#fi
        
function testing_fnc ()
{
   exit 0
}       
#testing_fnc "enp0s3"
#exit 1
#============================================================================================================
#============================================================================================================

#echo -e "1 - Install SertCenter\n2 - Customize Sert. Center\n3 - Get server sertif\n4 - Server config-file\n\
#5 - Start OpenVPN Server\n6 - Enable ip_forwarding\n7 - Configuring the firewall\n* - Exit"
#read -p "Enter a number: " number

# Configuring the firewall
# $1 - network interface
function ConfiguringFirewall ()
{
        # use ip a (or ip -br a) for see network interface name.
        # Result:
        #   1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
        #      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        #      inet 127.0.0.1/8 scope host lo
        #        valid_lft forever preferred_lft forever
        #      inet6 ::1/128 scope host noprefixroute 
        #        valid_lft forever preferred_lft forever
        #   2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
        #      link/ether 08:00:27:e4:26:a3 brd ff:ff:ff:ff:ff:ff
        #      inet 192.168.0.109/24 brd 192.168.0.255 scope global dynamic noprefixroute enp0s3
        #        valid_lft 5933sec preferred_lft 5933sec
        #      inet6 fe80::a00:27ff:fee4:26a3/64 scope link 
        #        valid_lft forever preferred_lft forever
        echo "$DATE_TIMESTAMP : start ConfiguringFirewall ()" >> "$LOGFILENAME"
        sudo iptables -A INPUT -i $1 -m state --state NEW -p udp --dport 1194 -j ACCEPT 2>> "$LOGFILENAME"
        sudo iptables -A INPUT -i tun+ -j ACCEPT 2>> "$LOGFILENAME"
        sudo iptables -A FORWARD -i tun+ -j ACCEPT 2>> "$LOGFILENAME"
        sudo iptables -A FORWARD -i tun+ -o $1 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>> "$LOGFILENAME"
        sudo iptables -A FORWARD -i $1 -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT 2>> "$LOGFILENAME"
        sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $1 -j MASQUERADE 2>> "$LOGFILENAME"
}

# Start OpenVPN Server service. After server.conf changes
# $1 - config-file name /etc/openvpn/server/server.conf or /etc/openvpn/server/client.conf
function StartOVPN ()
{
        echo "$DATE_TIMESTAMP : start StartOVPN ()" >> "$LOGFILENAME"
        sudo openvpn $1
        # Do you see "Initialization Sequence Completed" ?
}

# Install Sertification Center
function InstallOVPN_srv ()
{
        echo "$DATE_TIMESTAMP : start InstallOVPN ()" >> "$LOGFILENAME"
        sudo apt-get update 2>> "$LOGFILENAME"
        # This is server. Install openvpn and easy-rsa
        sudo apt-get install openvpn easy-rsa 2>> "$LOGFILENAME"
}

# Get server config-file
function GetServerConfigFile ()
{
        #sudo zcat /usr/share/doc/openvpn/examples/sample-config-files/server.conf.gz | sudo tee /etc/openvpn/server/server.conf
        echo "$DATE_TIMESTAMP : start GetServerConfigFile ()" >> "$LOGFILENAME"
        sudo cp /usr/share/doc/openvpn/examples/sample-config-files/server.conf /etc/openvpn/server/server.conf 2>> "$LOGFILENAME"
        echo "Your need editing server.config (/etc/openvpn/server/server.conf)!"
        echo -e "port 1194\n"\
                "proto udp\n"\
                "dev tun\n"\
                "ca ${SERVEROVPNDIR}ca.crt\n"\
                "cert ${SERVEROVPNDIR}server.crt\n"\
                "key ${SERVEROVPNDIR}server.key  # This file should be kept secret\n"\
                "dh none\n"\
                "topology subnet\n"\
                "server 10.8.0.0 255.255.255.0\n"\
                "ifconfig-pool-persist /var/log/openvpn/ipp.txt\n"\
                ";push "route 192.168.10.0 255.255.255.0"\n"\
                "cipher AES-256-GCM\n"\
                "auth SHA256\n"\
                ";push "redirect-gateway def1 bypass-dhcp"\n"\
                "keepalive 10 120\n"\
                "tls-crypt ${SERVEROVPNDIR}ta.key # This file is secret\n"\
                "user nobody\n"\
                "group nogroup\n"\
                "persist-key\n"\
                "persist-tun\n"\
                "status /var/log/openvpn/openvpn-status.log\n"\
                "verb 3\n"\
                "explicit-exit-notify 1" | sed 's/^[[:space:]]*//' >  "$SERVERCONFFILENAME"
}

# Customize Sert. Center
function CustomSertCenter ()
{
        #date_timestamp=$(date +"%Y-%m-%d %H:%M:%S")
        echo "$DATE_TIMESTAMP : start CustomSertCenter () " >> "$LOGFILENAME"
        sudo mkdir /etc/openvpn/easy-rsa 2>> "$LOGFILENAME"
        sudo mkdir /etc/openvpn/easy-rsa/pki/ 2>> "$LOGFILENAME"

        sudo cp -R /usr/share/easy-rsa /etc/openvpn/ 2>> "$LOGFILENAME"
        cd /etc/openvpn/easy-rsa/ 2>> "$LOGFILENAME"
        # create pki-directory and required files
        sudo ./easyrsa init-pki 2>> "$LOGFILENAME"
        # create certification authority key
        sudo ./easyrsa build-ca 2>> "$LOGFILENAME"
        # create Diffy-Hoffman key
        sudo ./easyrsa gen-dh 2>> "$LOGFILENAME"
        # create Hash-based Message Authentication Code (HMAC) key for TLS-authority
        sudo openvpn --genkey --secret /etc/openvpn/easy-rsa/pki/ta.key 2>> "$LOGFILENAME"
        # create cancellation certificate
        sudo ./easyrsa gen-crl 2>> "$LOGFILENAME"
}

# Get server sertificate
function GetServerSertificate ()
{
        #date_timestamp=$(date +"%Y-%m-%d %H:%M:%S")
        echo "$DATE_TIMESTAMP : start GetServerSertificate () " >> "$LOGFILENAME"
        cd /etc/openvpn/easy-rsa/ 2>> "$LOGFILENAME"

        sudo ./easyrsa build-server-full server nopass 2>> "$LOGFILENAME"

        # copy certificates to server directory
        sudo cp ./pki/ca.crt /etc/openvpn/server/ca.crt 2>> "$LOGFILENAME"
        sudo cp ./pki/dh.pem /etc/openvpn/server/dh.pem 2>> "$LOGFILENAME"
        sudo cp ./pki/crl.pem /etc/openvpn/server/crl.pem 2>> "$LOGFILENAME"
        sudo cp ./pki/ta.key /etc/openvpn/server/ta.key 2>> "$LOGFILENAME"
        sudo cp ./pki/issued/server.crt /etc/openvpn/server/server.crt 2>> "$LOGFILENAME"
        sudo cp ./pki/private/server.key /etc/openvpn/server/server.key 2>> "$LOGFILENAME"
}

echo -e "1 - Install SertCenter\n2 - Customize Sert. Center\n3 - Get server sertif\n4 - Server config-file\n\
5 - Start OpenVPN Server\n6 - Enable ip_forwarding\n7 - Configuring the firewall\n* - Exit"
read -p "Enter a number: " number
case $number in
        1)
                echo 'pattern 1'
                #exit 1
                InstallOVPN_srv
                ;;
        2)
                echo 'pattern 2'
                #exit 1
                CustomSertCenter
                ;;
        3)
                echo 'pattern 3'
                #exit 1
                GetServerSertificate
                ;;
        4)
                echo 'pattern 4'
                #exit 1         
                GetServerConfigFile
                ;;
        5)
                echo 'pattern 5'
                echo "Using /etc/openvpn/server/server.conf Server OVPN config-file"
                # Start OpenVPN Server service. After server.conf changes.
                StartOVPN "$SERVERCONFFILENAME" 2>> "$LOGFILENAME"
                echo "Do you see /Initialization Sequence Completed/?"
                ;;
        6)
                echo 'pattern 6'
                #exit 1
                # Enable ip_forwarding
                sudo sysctl -w net.ipv4.ip_forward=1 2>> "$LOGFILENAME"
                ;;
        7)
                echo 'pattern 7'
                #exit 1
                ConfiguringFirewall enp0s3
                ;;
        *)
                echo 'Exit!'
                ;;
esac

echo 'The end of fquest!'
