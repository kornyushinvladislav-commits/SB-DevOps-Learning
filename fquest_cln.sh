#! /bin/bash

echo "Hello, $USER!"

#ovpnclientname="ovpn-client-3"
read -p "Enter client name: " ovpnclientname

KEYDIR="/etc/openvpn/easy-rsa/clients/"
EASYRSADIR="/etc/openvpn/easy-rsa/"
OVPNDIR="/etc/openvpn/client/${ovpnclientname}"
LOGFILENAME="/home/${USER}/log/${ovpnclientname}.log"
CONFFILENAME="${KEYDIR}/${ovpnclientname}.ovpn"
DATE_TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

sudo mkdir "$OVPNDIR" 2>> "$LOGFILENAME"

echo "${DATE_TIMESTAMP} ::: BEGIN" >> "$LOGFILENAME"
sudo mkdir /home/$USER/log 2>> "$LOGFILENAME"
sudo chmod -R a+rwx "$OVPNDIR" 2>> "$LOGFILENAME"
#sudo mkdir "$KEYDIR" >> "$LOGFILENAME"
#sudo chmod -R a+rwx "$KEYDIR" >> "$LOGFILENAME"

function Install_OVPNclient ()
{
        echo "$DATE_TIMESTAMP : start InstallOVPN ()" >> "$LOGFILENAME"
        sudo apt-get update 2>> "$LOGFILENAME"
        # This is client. Install only openvpn
        sudo apt-get install openvpn 2>> "$LOGFILENAME"
        # To store the configuration firewall wee need iptables and iptables-persistent
        sudo apt-get install iptables iptables-persistent 2>> "$LOGFILENAME"
}

# Get server sertificate
function GetClientSertificate ()
{
        echo "$DATE_TIMESTAMP : start GetServerSertificate ()" >> "$LOGFILENAME"

        source "$EASYRSADIR"pki/vars
        #$EASYRSADIR/easyrsa build-client-full $ovpnclientname nopass

        #sudo mkdir "$KEYDIR" 2>> "$LOGFILENAME"
        #sudo chmod -R a+r "$KEYDIR" 2>> "$LOGFILENAME"

        # Create client keys
        sudo rm -R "$OVPNDIR" 2>> "$LOGFILENAME"
        sudo mkdir "$OVPNDIR" 2>> "$LOGFILENAME"
        sudo chmod -R a+r "$OVPNDIR" 2>> "$LOGFILENAME"

        cd /etc/openvpn/easy-rsa 2>> "$LOGFILENAME"
        export EASYRSA_CERT_EXPIRE=1460 2>> "$LOGFILENAME"

        # Copy keys for client deb-package
        sudo ./easyrsa build-client-full $ovpnclientname nopass 2>> "$LOGFILENAME"
        sudo chmod -R a+r ./pki/ 2>> "$LOGFILENAME"

        sudo cp ./pki/issued/"$ovpnclientname".crt ./pki/private/"$ovpnclientname".key ./pki/ca.crt ./pki/ta.key "$OVPNDIR" 2>> "$LOGFILENAME"
}
function GetClientConfigFile ()
{
        echo "$DATE_TIMESTAMP : start GetClientConfigFile ()" >> "$LOGFILENAME"
        sudo chmod -R a+rwx "$OVPNDIR" 2>> "$LOGFILENAME"

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
                <(echo -e "<ca>") \
                "$OVPNDIR/ca.crt" \
                <(echo -e "</ca>\n<cert>") \
                "$OVPNDIR/$ovpnclientname.crt" \
                <(echo -e "</cert>\n<key>") \
                "$OVPNDIR/$ovpnclientname.key" \
                <(echo -e "</key>\n<tls-crypt>") \
                "$OVPNDIR/ta.key" \
                <(echo -e "</tls-crypt>") \
                >> "$OVPNDIR/base.ovpn"

        #sudo chmod -R a+rwx "$OVPNDIR" 2>> "$LOGFILENAME"
}

# Start OpenVPN Client service. After client.ovpn changes
# $1 - config-file name /etc/openvpn/client/client.ovpn
function StartClientOVPN ()
{
        echo "$DATE_TIMESTAMP : start StartClientOVPN ()" >> "$LOGFILENAME"
        sudo openvpn $1
}

#Install_OVPNclient

sudo chmod -R a+r /etc/openvpn/easy-rsa/clients/

GetClientSertificate
GetClientConfigFile
StartClientOVPN "${OVPNDIR}/base.ovpn"
