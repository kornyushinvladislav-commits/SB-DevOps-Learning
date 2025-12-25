#! /bin/bash

echo "Hello, $USER!"

#ovpnclientname="ovpn-client-3"
read -p "Enter client name: " ovpnclientname

OVPNDIR="/etc/openvpn/client/$ovpnclientname"
LOGFILENAME="/home/$USER/log/$ovpnclientname.log"
#CONFFILENAME="${OVPNDIR}/client-1.ovpn"
CONFFILENAME="${OVPNDIR}/${ovpnclientname}.ovpn"
DATE_TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
KEYDIR="/etc/openvpn/easy-rsa/clients/"
EASYRSADIR="/etc/openvpn/easy-rsa/"

sudo mkdir "$OVPNDIR" 2>> "$LOGFILENAME"

echo "'$DATE_TIMESTAMP' : start ConfiguringFirewall ()" >> "$LOGFILENAME"
sudo mkdir /home/$USER/log 2>> "$LOGFILENAME"
sudo chmod -R a+rwx "$OVPNDIR" >> "$LOGFILENAME"
sudo mkdir "$KEYDIR" >> "$LOGFILENAME"
sudo chmod -R a+rwx "$KEYDIR" >> "$LOGFILENAME"

function Install_OVPNclient ()
{
        echo "$DATE_TIMESTAMP : start InstallOVPN ()" >> "$LOGFILENAME"
        sudo apt-get update 2>> "$LOGFILENAME"
        # This is client. Install only openvpn
        sudo apt-get install openvpn 2>> "$LOGFILENAME"
        # To store the configuration firewall wee need iptables and iptables-persistent
        sudo apt-get install iptables iptables-persistent 2>> "$LOGFILENAME"
}

function GetClientConfigFile ()
{
        echo "$DATE_TIMESTAMP : start GetClientConfigFile ()" >> "$LOGFILENAME"
        echo "Your need editing server.config (/etc/openvpn/client/client-X.ovpn)!"
        sudo chmod -R a+rwx "$KEYDIR" >> "$LOGFILENAME"
        echo -e "client\n"\
                "proto udp\n"\
                "dev tun\n"\
                "remote 192.168.0.109 1194\n"\
                "resolv-retry infinite\n"\
                "nobind\n"\
                "user nobody\n"\
                "group nogroup\n"\
                "persist-key\n"\
                "persist-tun\n"\
                "redirect-gateway def1 bypass-dhcp\n"\
                "remote-cert-tls server\n"\
                "cipher AES-256-GCM\n"\
                "auth SHA256\n"\
                "tls-crypt ta.key 1\n"\
                "key-direction 1\n"\
                "verb 3" | sed 's/^[[:space:]]*//' > "$CONFFILENAME"

        cat "$CONFFILENAME" \
                <(echo -e '<ca>') \
                ${KEYDIR}ca.crt \
                <(echo -e '</ca>\n<cert>') \
                ${KEYDIR}client.crt \
                <(echo -e '</cert>\n<key>') \
                ${KEYDIR}client.key \
                <(echo -e '</key>\n<tls-crypt>') \
                ${KEYDIR}ta.key \
                <(echo -e '</tls-crypt>') \
                >> "${KEYDIR}base.ovpn"
}

# Get server sertificate
function GetClientSertificate ()
{
        echo "$DATE_TIMESTAMP : start GetServerSertificate ()" >> "$LOGFILENAME"

#       sudo chmod -R a+rwx "/etc/openvpn/easy-rsa/"
#       echo -e 'if [ -z "$EASYRSA_CALLER" ]; then\n' \
#               "\t echo 'You appear to be sourcing an Easy-RSA *vars* file. This is' >&2\n" \
#               "\t echo "no longer necessary and is disallowed. See the section called" >&2\n" \
#               "\t echo "*How to use this file* near the top comments for more details." >&2\n" \
#               "\t return 1\n" > "$EASYRSADIR/vars"
#       echo -e 'fi\n' \
#               'set_var EASYRSA_REQ_COUNTRY     "RUS"\n' \
#               'set_var EASYRSA_REQ_PROVINCE    "Moscow"\n' \
#               'set_var EASYRSA_REQ_CITY        "Moscow City"\n' \
#               'set_var EASYRSA_REQ_ORG "Copyleft Certificate Co"\n' \
#               'set_var EASYRSA_REQ_EMAIL       "me@example.net"\n' \
#               'set_var EASYRSA_REQ_OU          "LLC"\n' \
#               'set_var EASYRSA_ALGO            ec\n' \
#               'set_var EASYRSA_DIGEST          "sha256"'  | sed 's/^[[:space:]]*//' >> "$EASYRSADIR/vars"

        source vars
        $EASYRSADIR/easyrsa build-client-full $ovpnclientname nopass


        sudo mkdir "$KEYDIR" >> "$LOGFILENAME"
        sudo chmod -R a+rwx "$KEYDIR" >> "$LOGFILENAME"

        # Copy keys for client deb-package      
        sudo cp /etc/openvpn/easy-rsa/pki/ca.crt ${KEYDIR} >> "$LOGFILENAME"
        sudo cp /etc/openvpn/easy-rsa/pki/private/ca.key ${KEYDIR} >> "$LOGFILENAME"
        sudo cp /etc/openvpn/server/ta.key ${KEYDIR} >> "$LOGFILENAME"

        password=""
        sudo rm -R "$OVPNDIR" >> "$LOGFILENAME"
        sudo mkdir "$OVPNDIR" >> "$LOGFILENAME"
        cd /etc/openvpn/easy-rsa >> "$LOGFILENAME"
        #sudo export EASYRSA_CERT_EXPIRE=1460 >> "$LOGFILENAME"
        sudo ./easyrsa build-client-full $ovpnclientname nopass >> "$LOGFILENAME"
        sudo cp ./pki/private/"$ovpnclientname".key ./pki/ca.crt ./pki/ta.key "$OVPNDIR" >> "$LOGFILENAME"
        sudo chmod -R a+r "$OVPNDIR" >> "$LOGFILENAME"

        #sudo cp /etc/openvpn/easy-rsa/pki/issued/server.crt ${KEYDIR}client.crt >> "$LOGFILENAME" #!!!!!!!!!!
        #sudo cp /etc/openvpn/easy-rsa/pki/private/server.key ${KEYDIR}client.key >> "$LOGFILENAME" #!!!!!!!!!!
}

# Start OpenVPN Client service. After client.ovpn changes
# $1 - config-file name /etc/openvpn/client/client.ovpn
function StartClientOVPN()
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

Install_OVPNclient
GetClientSertificate
GetClientConfigFile
StartClientOVPN $CONFFILENAME

