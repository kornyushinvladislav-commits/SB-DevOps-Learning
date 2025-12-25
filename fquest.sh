#! /bin/bash

echo "Hello, $USER!"

SERVEROVPNDIR="/etc/openvpn/server/"
LOGFILENAME="/home/fquest/log/fquest.log"
SERVERCONFFILENAME="${SERVEROVPNDIR}server.conf"
DATE_TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
EASYRSADIR="/etc/openvpn/easy-rsa/"

echo "'$DATE_TIMESTAMP' : start ConfiguringFirewall ()" >> "$LOGFILENAME"
sudo mkdir /home/$USER/log 2>> "$LOGFILENAME"

#============================================================================================================
#============================================================================================================
function testing_fnc ()
{
   exit 0
}
#testing_fnc "enp0s3"
#exit 1
#============================================================================================================
#============================================================================================================

# Configuring the firewall
# $1 - network interface
function ConfiguringFirewall ()
{
        echo "$DATE_TIMESTAMP : start ConfiguringFirewall ()" >> "$LOGFILENAME"
        sudo iptables -A INPUT -i $1 -m state --state NEW -p udp --dport 1194 -j ACCEPT 2>> "$LOGFILENAME"
        sudo iptables -A INPUT -i tun+ -j ACCEPT 2>> "$LOGFILENAME"
        sudo iptables -A FORWARD -i tun+ -j ACCEPT 2>> "$LOGFILENAME"
        sudo iptables -A FORWARD -i tun+ -o $1 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>> "$LOGFILENAME"
        sudo iptables -A FORWARD -i $1 -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT 2>> "$LOGFILENAME"
        sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $1 -j MASQUERADE 2>> "$LOGFILENAME"

        # Need save this configuration
        sudo netfilter-persistent save 2>> "$LOGFILENAME"
}

function MakeVarsFile ()
{
        sudo chmod -R a+rwx "/etc/openvpn/easy-rsa/"
        echo -e 'if [ -z "$EASYRSA_CALLER" ]; then\n' \
                "\t echo 'You appear to be sourcing an Easy-RSA *vars* file. This is' >&2\n" \
                "\t echo "no longer necessary and is disallowed. See the section called" >&2\n" \
                "\t echo "*How to use this file* near the top comments for more details." >&2\n" \
                "\t return 1\n" > "$EASYRSADIR/vars"
        echo -e 'fi\n' \
                'set_var EASYRSA_REQ_COUNTRY     "RUS"\n' \
                'set_var EASYRSA_REQ_PROVINCE    "Moscow"\n' \
                'set_var EASYRSA_REQ_CITY        "Moscow City"\n' \
                'set_var EASYRSA_REQ_ORG "Copyleft Certificate Co"\n' \
                'set_var EASYRSA_REQ_EMAIL       "me@example.net"\n' \
                'set_var EASYRSA_REQ_OU          "LLC"\n' \
                'set_var EASYRSA_ALGO            ec\n' \
                'set_var EASYRSA_DIGEST          "sha256"'  | sed 's/^[[:space:]]*//' >> "$EASYRSADIR/vars"
}

# Start OpenVPN Server service. After server.conf changes
# $1 - config-file name /etc/openvpn/server/server.conf or /etc/openvpn/server/client.conf
function StartOVPN ()
{
        pid_ovpn="$(pidof openvpn)"
        if [ "$pid_ovpn" -gt 0 ]; then
                echo 'sudo kill -9 "$(pidof openvpn)"' >> "$LOGFILENAME"
                sudo kill -9 "$(pidof openvpn)" 2>> "$LOGFILENAME"
        else
                echo 'Not found old openvpn process!'
        fi

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
        # To store the configuration firewall wee need iptables-persistent       
        sudo apt-get install iptables-persistent 2>> "$LOGFILENAME"
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

function start_proc_manualy ()
{
        echo -e '1 - Install SertCenter\n2 - Customize Sert. Center\n3 - Get server sertif\n4 - Server config-file\n5 - Start OpenVPN Server\n6 - Enable ip_forwarding\n7 - Configuring the firewall\n* - Exit'
        read -p 'Enter a number: ' number
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
                        echo 'Using "$SERVERCONFFILENAME" Server OVPN config-file'
                        # Start OpenVPN Server service. After server.conf changes.
                        StartOVPN "$SERVERCONFFILENAME" 2>> "$LOGFILENAME"
                        echo 'Do you see /Initialization Sequence Completed/?'
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
                        # ip a (or ip -br a) for see network interface name.
                        ConfiguringFirewall enp0s3
                        ;;
                *)
                        echo 'Exit!'
                        ;;
        esac
}

function start_proc ()
{
        echo '-> ::::::   Start process!'
        InstallOVPN_srv
        echo '-> ::::::   MakeVarsFile'
        MakeVarsFile
        echo '-> ::::::   Customaze sertificate center'
        CustomSertCenter
        echo '-> ::::::   Get server sertificate files'
        GetServerSertificate
        echo '-> ::::::   Make server configuration file'
        GetServerConfigFile
        echo '-> ::::::   Enable ip_forwarding'
        # Enable ip_forwarding
        sudo sysctl -w net.ipv4.ip_forward=1 2>> "$LOGFILENAME"
        echo '-> ::::::  Configuring firewall'
        # ip a (or ip -br a) for see network interface name.
        ConfiguringFirewall enp0s3
        echo '-> ::::::   Start OVPN-file'
        echo 'Using "$SERVERCONFFILENAME" OVPN server config-file'
        # Start OpenVPN Server service. After server.conf changes.
        StartOVPN "$SERVERCONFFILENAME" 2>> "$LOGFILENAME"
        echo 'Do you see /Initialization Sequence Completed/?'
}

start_proc_manualy
#start_proc
echo 'The end of fquest!'

