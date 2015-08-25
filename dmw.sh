#!/bin/bash
# Do my work script

#Please keep under 80 lines of width

#Arrays needed
declare -a INTERFACE
declare -a IP_INTERFACE
declare -a NETMASK_INTERFACE
declare -a HOST_SUFIX
declare -a INT_TYPE
declare -a BOND_SLAVES
declare -a VOL_NAME
declare -a VOL_SIZE
declare -a VG_NAME
declare -a VG_PVS
declare -a ROUTE_COMMENT
declare -a ROUTE_DESTINATION
declare -a ROUTE_GW
declare -a ROUTE_INT

# Load template
if [ -f template ];
then
    . template
else
    echo "-----------------"
    echo "No template found"
    echo "-----------------"
    echo "---------------------------"
    echo "MOST TASKS WILL FAIL!!!"
    echo "EXCECUTE BY YOUR OUWN RISK"
    echo "---------------------------"
    echo ""
fi

#Linux distribution
RH=/etc/redhat-release
SLES=/etc/SuSE-release
EDS=/etc/eds-release
if [ -f $RH ];
then
    FLAVOR=RH;
    echo -n "RH flavor loaded: "
    cat $RH
elif [ -f $SLES ];
then
    echo -n "SLES flavor loaded"
    cat $SLES

    FLAVOR=SLES;
else
    echo "Not valid OS found";
    #exit 1
fi
if [ -f $EDS ];
then
    echo -n "Gold Disk release: "
    cat $EDS
fi

#Lets test if we are on a vm (vmware)
lspci | grep -i vmware 2>/dev/null 1>&2 && echo "This server is a Virtual\
 Machine of VMWare" && VM="yes"

function dmw_show_hw_info()
{
######## HARD INFO #########
MOTHER_SERIAL=$(dmidecode -t 2 | awk ' $1 == "Serial" { print $3 }')
VENDOR=$(dmidecode -t 0 | awk ' $1 == "Vendor:" { print $2 }')
BIOS=$(dmidecode -t 0 | awk ' $1 == "BIOS" && $2 ==  "Revision:"  { print $3 }')
FW_REV=$(dmidecode -t 0 | awk ' $1 == "Firmware" { print $3 }')
PRODUCT=$(dmidecode -t 1 | awk -F':' ' $1 ~ "Product Name"  { print $2 }')
CHASSIS_SERIAL=$(dmidecode -t 3 | awk ' $1 == "Serial" { print $3 }')
CORES=$(cat /proc/cpuinfo| grep processor | wc -l)
RAM_MB=$(cat /proc/meminfo | awk '{ print $2 }' | head -n 1)
RAM=$(($RAM_MB/1000))

echo "Hardware resume:"
echo "==============="
if [[ -n $VENDOR && -n $PRODUCT ]];
then
    echo "Vendor and Product: $VENDOR | $PRODUCT"
fi
if [[ -n $CORES && -n $RAM ]];
then
    echo "Cores: $CORES | RAM: $RAM MB"
fi
if [[ -n $CHASSIS_SERIAL ]];
then
    echo "Serial: $CHASSIS_SERIAL"
fi
if [[ -n $MOTHER_SERIAL ]];
then
    echo "Mother Serial: $MOTHER_SERIAL"
fi
if [[ -n $FW_REV ]];
then
    echo "Firmware: $FW_REV"
fi
if [[ -n $BIOS ]];
then
    echo "BIOS version: $BIOS"
fi
echo "==============="
}
#Showing hw resume
dmw_show_hw_info

#Services init files
if [ $FLAVOR == "RH" ];
then
    NTP_INIT=ntpd;
elif [ $FLAVOR == "SLES" ];
then
    NTP_INIT=ntp;
fi

SSHD_INIT=sshd;
NETWORK_INIT=networking;
POSTFIX_INIT=postfix;
KDUMP_INIT=kdump;
MULTIPATH_INIT=multipathd;

#Commands variables
ICFG=$(which ifconfig)
IFUP=$(which ifup)
CHKCONFIG=$(which chkconfig)
USERADD=$(which useradd)
CHPASSWD=$(which chpasswd)
HOSTNAME=$(which hostname)
LVEXTEND=$(which lvextend)
LVDISPLAY=$(which lvdisplay)
LVCREATE=$(which lvcreate)
VGDISPLAY=$(which vgdisplay)
VGCREATE=$(which vgcreate)
FDISK=$(which fdisk)
ARCH=$(which arch)
SWAPON=$(which swapon)
SWAPOFF=$(which swapoff)
MKSWAP=$(which mkswap)
MKFS=$(which mkfs)
ALTERNATE=$(which alternate_boot)
SYSTOOL=$(which systool)
RPM=$(which rpm)
MULTIPATH=$(which multipath)
GETENT=$(which getent)
SYSCTL=$(which sysctl)

#Resize depends on the RH version
RESIZE=$(which resize4fs 2>/dev/null)
if [[ $? != 0 ]];
then
    RESIZE=$(which resize2fs)
fi


#File variables
NET_FILE=/etc/sysconfig/network
NET_R_FILE=/etc/sysconfig/network-scripts/
BONDING_FILE=bonding.conf
MODPROBE_FILE=/etc/modprobe.conf
NTP_FILE=/etc/ntp.conf
NTP_STEPS_FILE=/etc/ntp/step-tickers
LOCALTIME_FILE=/etc/localtime
SSHD_FILE=/etc/ssh/sshd_config
HOSTS_FILE=/etc/hosts
MULTIPATH_FILE=/etc/multipath.conf
DNS_FILE=/etc/resolv.conf
SYSCTL_FILE=/etc/sysctl.conf
SUDO_FILE=/etc/sudoers
SELINUX_FILE=/etc/sysconfig/selinux
ACCESS_FILE=/etc/security/access.conf
LIMITS_FILE=/etc/security/limits.conf
CLOCK_FILE=/etc/sysconfig/clock
SNMP_FILE=/etc/snmp/snmpd.conf
POSTFIX_FILE=/etc/postfix/main.cf
GRUB_FILE=/boot/grub/grub.conf
SYSSTAT_FILE=/etc/cron.d/sysstat
SELINUX_FILE=/etc/selinux/config
MULTIPATH_FILE=/etc/multipath.conf
ALTERNATE_FILE=/etc/sysconfig/alternate_boot
UDEV_RULES=/etc/udev/rules.d/
UDEV_RULE_NET=$UDEV_RULES"70-persistent-net.rules"
FSTAB=/etc/fstab

#Paths
ZONE_PATH=/usr/share/zoneinfo/
INIT_PATH=/etc/init.d/
MODPROBE_PATH=/etc/modprobe.d/

if [ $FLAVOR == "RH" ];
then
    INTERFACES_PATH=/etc/sysconfig/network-scripts/
elif [ $FLAVOR == "SLES" ];
then
    INTERFACES_PATH=/etc/sysconfig/network/
fi

#Logs
LOG_ERROR=/tmp/error.dmw.log
LOG_OUTPUT=/tmp/output.dmw.log
LOG_EXECUTED=/tmp/executed.dmw.log

################GUI Variables############################
GREEN=`tput setf 2`
WHITE=`tput setf 9`
RED=`tput setf 4`
WHITE=`tput setf 9`
ORANGE=`tput setf 7`
#################GUI Functions###########################


function put_ok ()
{
tput cuf $(( $(tput cols) - 60 ));
echo "[$GREEN Ok $WHITE]" | tee -a log
tput cuf 0;
#tput rc;
log_output "-----> [Ok]"
}

function put_fail ()
{
tput cuf $(( $(tput cols) - 60 ));
echo "[$RED Fail $WHITE]"
tput cuf 1;
#tput rc;
log_output "----->  [Fail]"
}
function put_warning ()
{
tput cuf $(( $(tput cols) - 60 ));
echo "[$ORANGE Warning $WHITE]"
tput cuf 1
log_output "------> [Warning]"
}
function task_message ()
{
log_output $@
#TODO: cut message if larger than desired
tput cuf 1
tput bold;
    echo -n $@
#tput sc;
tput sgr0;
}

function alert ()
{
tput setb 4
tput bold
echo $@
tput sgr0
echo -e "\n"
}

##### TODO #####
function time_log()
{
large=$(date +"%d-%m-%y %H:%m");
echo -n $large;
}

function log_output ()
{
time_log >> $LOG_OUTPUT;
echo $@ >> $LOG_OUTPUT;
}

###############################################################################
###############################################################################
############################# Internal functions  #############################
###############################################################################
###############################################################################

# Most of these functions are very simple, and some of them could be
# replaced by only one command or an alias. But using the functions
# keeps the code cleanest

################################## LVM ########################################

# VG FREE PE:
# Take a vg name and return free PEs

function vg_free_pe ()
{
# $1 vg name
if [[ $# == 1 ]];
then
	$VGDISPLAY $1 2>/dev/null 1>&2
	if [[ $? == 0 ]];
	then
		PES=$($VGDISPLAY -c $1 | cut -d: -f16)
		echo $PES;
		return 0;
	else
		echo "VG not found or error";
		return 1;
	fi
fi
}

# VG PE SIZE
# Returns the pe size of a given vg

function vg_pe_size ()
{
# $1 vg name
if [[ $# == 1 ]];
then
    $VGDISPLAY $1 2>/dev/null 1>&2
	if [[ $? == 0 ]];
	then
		PE_SIZE=$(( $($VGDISPLAY -c $1 | cut -d: -f13) / 1024 ))
		echo $PE_SIZE;
		return 0;
	else
		echo "VG not found or error";
        return 1
	fi
fi
}



# VG FREE:
# Take a vg name and return free size in gb
# sample:vg_free vg00
# returns: 15 (15 gb free)

function vg_free ()
{
# $1 vg name
# $2 if $2 == MB then the output will be in MB (more accurate)

$VGDISPLAY $1 2>/dev/null 1>&2
if [[ $? == 0 ]];
then
	FREE_PE=$(vg_free_pe $1)
	PE_SIZE=$(vg_pe_size $1)
	FREE_SIZE_MB=$(($FREE_PE*$PE_SIZE))
	FREE_SIZE_GB=$(($FREE_SIZE_MB/1024))
	if [[ $2 == "MB" ]];
	then
		echo $FREE_SIZE_MB;
		return 0;
	else
		echo $FREE_SIZE_GB;
		return 0;
	fi
else
	echo 0;
	return 1;
fi
}

# LV SIZE:
# Take a lv full path name and returns de size in MB
# (also in PE or GB if needed)

function lv_size ()
{
# $1 lv full path (like /dev/vg00/rootvol)
# $2 [GB|LE] optionally you can choose GB or LE (MB by default)
if [[ -b $1 ]];
then
    $LVDISPLAY $1 2>/dev/null 1>&2;
    if [[ $? == 0 ]];
    then
        VG=$($LVDISPLAY -c $1| cut -d: -f2)
        VG_PE_SIZE=$(vg_pe_size $VG)
        LV_LES=$($LVDISPLAY -c $1 | cut -d: -f8)
        LV_SIZE_MB=$(($LV_LES*$VG_PE_SIZE))
        LV_SIZE_GB=$(($LV_SIZE_MB/1024))
        if [[ $2 == "GB" ]];
        then
            echo $LV_SIZE_GB;
            return 0;
        elif [[ $2 == "LE" ]];
        then
            echo $LV_LES;
            return 0;
        else
            echo $LV_SIZE_MB;
            return 0;
        fi
    else
        echo "Bad LV path of non existent"
        return 1;
        fi
else
    echo "LV didn't found!";
    return 2;
fi
}

# CREATE LV
# Create a new LV on a given VG
# $1 lv name
# $2 lv size
# $3 vg name

function create_lv ()
{
# $1 lvname
# $2 size in MB
# $3 vgname
vg_size=$(vg_free $3 "MB")
vg_pe=$(vg_pe_size $3)
if [[ $2 -le $vg_size ]];
then
    task_message "Creating LV $1"
    $LVCREATE -L $2"M" -n $1 $3 2>/dev/null 1>&2
    if [ $? == 0 ];
    then
        $MKFS /dev/$3/$1 2>/dev/null 1>&2
        put_ok;
        return 0;
    else
        put_fail;
        return 1;
    fi
else
    round=$((LV_CREATION_ROUND*vg_pe))
    new_size=$(($2-$round))
    if [[ $vg_size -ge $new_size ]];
    then
        task_message "Creating LV $1, size round: $new_size M instead of $2M"
        $LVCREATE -n $1 -L $new_size"M" $3  2>/dev/null 1>&2
        if [[ $? -eq 0 ]];
        then
            put_ok;
            return 0;
        else
            put_fail;
            return 1;
        fi
    else
        task_message "No available space on $3"
        put_fail;
        return 1;
    fi
fi
}

##################################################################
########################## Check tasks ###########################
##################################################################
function check_hostname ()
{
    task_message "Checking hostname:"
    hostname=$(hostname -f)
    hostname_infile=$(cat $NET_FILE | awk -F'=' ' $1 == "HOSTNAME" {print $2}')
    echo -e "\n\t\tCurrent hostname:\t\t$hostname"
    echo -e "\t\tConfigured hostname:\t\t$hostname_infile"
    echo -e "\t\tRequired hostname:\t\t$NAME"
    if [[ $hostname_infile -eq $NAME ]];
    then
        echo ""
        task_message "Hostname is configured as required"
        echo ""
        if [[ $NAME == $hostname ]];
        then
            task_message "also the running hostname:";
            put_ok;
        else
            task_message "but the running hostname is wrong";
            put_warning;
        fi
    fi
}


function check_cores ()
{
    task_message "Checking Cores:"
    echo -n "$CORES"; put_ok
}


function check_all ()
{
    check_hostname
    check_cores

}
##################################################################
########################## BUILD TASKS ###########################
##################################################################

################ Easy tasks functions ##################

#Set hostname
function dmw_set_hostname ()
{
#Set the hostname (overwriting the hostname file))

task_message "Setting hostname: $NAME";
if [ $FLAVOR == "RH" ];
then
echo "NETWORKING=yes
NETWORKING_IPV6=no
HOSTNAME="$NAME.$DOMAIN"
"> $NET_FILE
elif [ $FLAVOR == "SLES" ];
then
    echo "$NAME.$DOMAIN" > /etc/HOSTNAME
fi
$HOSTNAME $NAME && put_ok

}
function dmw_set_hosts ()
{
#Set additional entries for /etc/hosts file
if [[ -n $HOSTS ]];
then
    task_message "Setting hosts on $HOSTS_FILE"
    echo "" >> $HOSTS_FILE
    echo "#Additional hosts" >> $HOSTS_FILE
    echo $HOSTS >> $HOSTS_FILE
    put_ok
fi
}
function dmw_set_gateway ()
{
task_message "Setting gateway: $GATEWAY";
if [[ $FLAVOR == "RH" ]];
then
	echo "GATEWAY=$GATEWAY" >> $NET_FILE;
elif [[ $FLAVOR == "SLES" ]];
then
	echo "default $GATEWAY" > $INTERFACES_PATH"routes";
fi
put_ok;
}

function dmw_set_localtime ()
{
#Set the time zone
task_message "Setting localtime: $ZONE"
mv -f $LOCALTIME_FILE $LOCALTIME_FILE.old
cp -f $ZONE_PATH$ZONE $LOCALTIME_FILE
echo "ZONE='$ZONE'" > $CLOCK_FILE
put_ok
}

function dmw_set_dns ()
{
#Set dns servers (overwriting)
task_message "Setting DNS:"
rm -f $DNS_FILE; touch $DNS_FILE;
for server in $DNS_SERVERS;
do
    echo "nameserver $server" >> $DNS_FILE;
done
echo "domain $DOMAIN" >> $DNS_FILE;
echo "search $DOMAIN" >> $DNS_FILE;
put_ok
}

function dmw_set_ntp()
{
#Set ntp servers

task_message "Setting NTP:"
rm -rf $NTP_FILE;

#Check if needed force version 3
if [[ ! -z $NTP_VERSION ]];
then
    VERSION="version $NTP_VERSION"
fi

for server in $NTP_SERVERS;
do
    echo "server $server $VERSION" >> $NTP_FILE;
done
################################################################################
#########################NTP CONFIG FILE########################################
################################################################################

cat << EOF >> $NTP_FILE
tinker panic 0
disable monitor

# For more information about this file, see the man pages
# ntp.conf(5), ntp_acc(5), ntp_auth(5), ntp_clock(5), ntp_misc(5), ntp_mon(5).

driftfile /var/lib/ntp/drift

# Permit time synchronization with our time source, but do not
# permit the source to query or modify the service on this system.
restrict default nomodify
restrict -6 default kod nomodify notrap nopeer noquery

# Permit all access over the loopback interface.  This could
# be tightened as well, but to do so would effect some of
# the administrative functions.
restrict 127.0.0.1
restrict -6 ::1

# Hosts on local network are less restricted.
#restrict 192.168.1.0 mask 255.255.255.0 nomodify notrap

# Use public servers from the pool.ntp.org project.
# Please consider joining the pool (http://www.pool.ntp.org/join.html).

#broadcast 192.168.1.255 autokey	# broadcast server
#broadcastclient			# broadcast client
#broadcast 224.0.1.1 autokey		# multicast server
#multicastclient 224.0.1.1		# multicast client
#manycastserver 239.255.254.254		# manycast server
#manycastclient 239.255.254.254 autokey # manycast client

# Enable public key cryptography.
#crypto

includefile /etc/ntp/crypto/pw

# Key file containing the keys and key identifiers used when operating
# with symmetric key cryptography.
keys /etc/ntp/keys

# Specify the key identifiers which are trusted.
#trustedkey 4 8 42

# Specify the key identifier to use with the ntpdc utility.
#requestkey 8

# Specify the key identifier to use with the ntpq utility.
#controlkey 8

# Enable writing of statistics records.
#statistics clockstats cryptostats loopstats peerstats
EOF
################################################################################

service $NTP_INIT restart 2>/dev/null 1>&2 && put_ok || put_fail

}

#Create secadmin
function dmw_create_secuser ()
{
#ToDo: Turn into generic user creation function
    #Create user
    task_message "Creating Sec User: $SECUSER"

    #Verify if the group exists
    $GETENT group $SECUSER_GROUP 2>/dev/null 1>&2;

    if [[ $? == 0 ]];
    then
        ADD_TO_GROUP="-g $SECUSER_GROUP"
    else
        ADD_TO_GROUP=""
    fi

    if [[ $SECUSER_CREATE_IF_NO_GROUP == "yes" ]];
    then
        $USERADD -m -s $SECUSER_SHELL -c $SECUSER_GECOS \
        $ADD_TO_GROUP $SECUSER 2>/dev/null 1>&2 && put_ok || put_fail
    else
        echo "$SECUSER_GROUP not found" && put_ok
    fi

    #Set password
    task_message "Setting Sec User password: "
    echo $SECUSER":"$SECUSER_PASSWORD | $CHPASSWD && put_ok || put_fail
}


function dmw_set_mail ()
{
#ToDo: extend for sendmail
task_message "Setting mail forwarder: "
#Set the mail relay host
if [ -f $POSTFIX_FILE ];
then
    sed -ie  '/^relayhost/ c relayhost = '$SMTP  $POSTFIX_FILE 2>/dev/null ;
    service $POSTFIX_INIT restart  2>/dev/null 1>&2 && put_ok || put_fail
else
    put_fail
    echo -e "\t$POSTFIX_FILE doesn't exists";
fi
}


function dmw_disable_rootlogin ()
{
#ToDo: Create enable rootlogin
#Disable root login from SSH
if [ $DISABLE_ROOT_SSH == "yes" ];
then
    task_message "Disabling SSH root login: "
    if [ -f $SSHD_FILE ];
    then
        grep -e 'PermitRootLogin no' $SSHD_FILE >/dev/null 2>&1
        if [ $? == 1 ];
        then
            sed -ie "s/#PermitRootLogin yes/PermitRootLogin no/" $SSHD_FILE 2>/dev/null;
            sed -ie "s/#UseDNS yes/UseDNS no/" $SSHD_FILE 2>/dev/null;
            service $SSHD_INIT restart 2>/dev/null 1>&2 && put_ok
        else
            put_ok
            echo -e "\t\tAlready disabled"
        fi
    else
        put_fail
        echo -e "\t\t$SSHD_FILE doesn't exist"
    fi
fi
}

function dmw_set_snmp ()
{

COMMUNIT_STRING="com2sec notConfigUser  default "
SNMP_LINE=$COMMUNIT_STRING$SNMP_STRING
#Set SNMP Community string
#It works even on not gold disk image
task_message "Setting SNMP:"
if [ -f $SNMP_FILE ];
then
    eval "sed -ie '/com2sec/ c $SNMP_LINE'  $SNMP_FILE" 2>/dev/null;
    #Verify if the change was effective
    grep $SNMP_STRING $SNMP_FILE >/dev/null 2>&1 && put_ok || put_fail;
fi
}

function dmw_root_passwd ()
{
if [[ -n $ROOTPASSWD || -n $1 ]];
then
    if [ -n $1 ]; then ROOTPASSWD=$1; fi
    task_message "Setting root passwd:"
    echo "root:$ROOTPASSWD" | $CHPASSWD
    if [ $? == 0 ];
    then
        put_ok
        alert "Root password set! Don't forgive!"
    else
        put_fail
        alert "Password root not set"
    fi
fi
}

function dmw_set_kdump ()
{
#Set the crashkernel parameter on the grub config file
task_message "Setting Kdump kernel parameter:"
sed -ie 's/crashkernel=auto/crashkernel='$KDUMP_PARAM'/' $GRUB_FILE 2>/dev/null;
if [ $? == 0 ];
then
    service $KDUMP_INIT restart 2>/dev/null 1>&2 && put_ok || put_fail
fi
}

function dmw_enable_sarlogin ()
{
task_message "Verifying SAR login: "
$RPM -q sysstat 2>/dev/null 1>&2
if [[ $? == 0 ]];
then
    echo -n " soft installed|"
    if [ -f $SYSSTAT_FILE ];
    then
        echo -n "crond file found"; put_ok
    else
        echo "cron.d file Not found";
        echo -e "\tCreating sysstat file for crond:"
        echo "# Run system activity accounting tool every 10 minutes" >> $SYSSTAT_FILE
        echo "*/10 * * * * root /usr/lib/sa/sa1 -S DISK 1 1" >> $SYSSTAT_FILE
        echo "# 0 * * * * root /usr/lib/sa/sa1 -S DISK 600 6 &" >> $SYSSTAT_FILE
        echo "# Generate a daily summary of process accounting at 23:53" >> $SYSSTAT_FILE
        echo "53 23 * * * root /usr/lib/sa/sa2 -A" >> $SYSSTAT_FILE
        cat /etc/cron.d/sysstat && put_fail || put_fail
    fi
else
    echo -n "soft not installed"; put_fail
fi
}

function dmw_disable_selinux ()
{
#ToDo: improve search if the parameteres are not set already
if [ $DISABLE_SELINUX == "yes" ];
then
    if [ $FLAVOR == "RH" ];
    then
        task_message "Disabling selinux (requires rebot):"
        (sed -ie 's/SELINUX=permissive/SELINUX=disabled/' $SELINUX_FILE 2>/dev/null\
        && sed -ie 's/audit=1/audit=1 selinux=0/' $GRUB_FILE) && put_ok || put_fail
    elif [ $FLAVOR == "SLES" ];
    then
        task_message "SuSE has selinux disabled by default:"
        put_ok
    fi
fi
}
function dmw_show_wwns ()
{
#ToDo Please improve: Show port state
if [[ $VM != "yes" ]]; then
task_message "Searching WWNs:"
wwn=$($SYSTOOL -c fc_host -v 2>/dev/null | grep "port_name" | cut -d'"' -f2)
$SYSTOOL -c fc_host -v 2>/dev/null 1>&2
if [ $? == 0 ];
then
    put_ok;
    echo ""
    echo -e "\tWWNs:"
    for i in $wwn; do echo -e "\t\t$i"; done
else
    echo -n " There are no wwns";put_fail;
fi
fi
}

function dmw_set_kernel_parameter ()
{
#$1 parameter
#$2 value

parameter=$1
value="$2 $3 $4 $5 $6"

if [[ ! $# -eq 2 ]];
then
    return 1;
fi
$SYSCTL $parameter 2>/dev/null 1>&2
if [[ $? == 0 ]];
then
    grep $parameter $SYSCTL_FILE 2>/dev/null 1>&2
    if [[ $? == 0 ]];
    then
        current_value=$(grep $parameter $SYSCTL_FILE|awk -F= '!/^#/ { print $2 }')
        if [[ $current_value != $value ]];
        then
            echo -e "\tThe current value: $current_value is equal to $value"
            return 0;
        fi
        echo -e "\tReplacing $current_value for $value on $parameter"
        sed -ie "/$parameter/ s/$current_value/ $value/"  $SYSCTL_FILE
    else
        echo -e "\tAdding parameter $1 = $2"
        echo "$parameter = $value" >> $SYSCTL_FILE
    fi
    $SYSCTL -p 2>/dev/null 1>&2
else
    echo  -e "\tThe parameter $1 isn't recognized by sysctl"; put_fail
fi

}


function dmw_set_multipaths ()
{
#ToDo: Please improve: search for diffrent multipath files for backward compat;
# create different function to only show multipath stanzas

task_message "Setting multipaths:"
if [ -f $MULTIPATH_FILE ];
then
    put_ok;
    (echo "multipaths {";
    $MULTIPATH -ll |grep mpath | while read line;do
        echo " multipath {";
        echo -n " wwid " ;
        echo $line |awk '{print $2}'|sed -e 's/(//' -e 's/)//';
        echo -n " alias " ;
        echo $line |awk '{print $1}';echo " }";
    done
    echo "}") >> $MULTIPATH_FILE
    $CHKCONFIG $MULTIPATH_INIT on
else
    echo -n "Multipath file doesn't exist"; put_fail;
fi
}

################## NETWORK FUNCTIONS #################

function dmw_set_int ()
{

#####missing: Detect Bond interfaces!!
# Use as follow:
# configure_int interface ip netmask
# sample:
# configure_int eth0 192.168.1.23 255.255.255.0 [bond]

$ICFG $1 2>/dev/null 1>&2

if [[ $? == 0 || $4 == "bond" ]];
then
    task_message "Configuring $1:"
    echo ""
    INT_FILE=$INTERFACES_PATH"ifcfg-$1"
    MAC=$(ifconfig $1 | grep HW | awk {'print $5'})
    echo -e "\tIP:$2"
    echo -e "\tNETMASK:$3"
    echo -e "\tMAC:$MAC"

    if [ -f $INT_FILE ];
    then
        rm -f $INT_FILE
    else
        echo -e "\tFile for $1 doesn't exists. Will be created"
        touch $INT_FILE
    fi

    echo "DEVICE=$1" >> $INT_FILE
    echo "IPADDR=$2" >> $INT_FILE
    echo "NETMASK=$3" >> $INT_FILE

    if [ $FLAVOR == "RH" ];
    then
        echo "ONBOOT=yes" >> $INT_FILE
    elif [ $FLAVOR == "SLES" ];
    then
        echo "STARTMODE=onboot" >> $INT_TYPE
    fi

    if [[ $4 != "bond" ]];
    then
        echo "HWADDR=$MAC" >> $INT_FILE
    fi

    task_message "Testing config:"

    $IFUP $1 2>/dev/null 1>&2 && put_ok || put_fail
    echo ""
else
    echo "$1 doesn't exists"
fi
}

function dmw_set_bonding ()
{
# Set the bonding configuration not the bond interfaces
task_message "Setting bonding module:"
for interface in $(seq 1 ${#INTERFACE[@]});
    do
        if [[ ${BOND_SLAVES[$interface]} != "" ]];
        then
            CONFIGURE_BONDS="yes"
            break
        else
            CONFIGURE_BONDS="no"
        fi
    done
if [[ $CONFIGURE_BONDS == "yes" ]];
then
    if [[ -d $MODPROBE_PATH ]];
    then
        BOND_FILE=$MODPROBE_PATH$BONDING_FILE
    else
        BOND_FILE=$MODPROBE_FILE
    fi
    echo ""
    for int in $(seq 1 ${#INTERFACE[@]});
    do
    if [[ ${INT_TYPE[$int]} == "bond" ]];
    then
        echo "alias ${INTERFACE[$int]} bonding" >> $BOND_FILE
        echo "options ${INTERFACE[$int]} mode=1 miimon=80" >> $BOND_FILE
        echo -en "\tfor ${INTERFACE[$int]}" && put_ok
    fi
    done
else
    echo -n "Not needed!"; put_ok
fi
}

function dmw_set_slave ()
{
# Use as follow
#   configure_slave int bond_int
# Sample:
#   configure_slave eth0 bond0

$ICFG $1 2>/dev/null 1>&2
if [ $? == 0 ];
then
    INT_FILE=$INTERFACES_PATH"ifcfg-$1"
    MAC=$(ifconfig $1 | grep HW | awk {'print $5'})
    if [ -f $INT_FILE ];
    then
        rm -f $INT_FILE
    fi
    echo "DEVICE=$1" >> $INT_FILE
    echo "HWADDR=$MAC" >> $INT_FILE
    echo "SLAVE=yes" >> $INT_FILE
    echo "MASTER=$2" >> $INT_FILE
    if [ $FLAVOR == "RH" ];
    then
        echo "ONBOOT=yes" >> $INT_FILE
    elif [ $FLAVOR == "SLES" ];
    then
        echo "STARTMODE=onboot" >> $INT_TYPE
    fi
    return 0
else
    return 1
fi
}

function dmw_set_bonds ()
{
#Configure the properly slaves
for int in $(seq 1 ${#INTERFACE[@]});
do
    if [[ ${BOND_SLAVES[$int]} != "" ]];
    then
        CONFIGURE_BONDS="yes"
        break
    else
        CONFIGURE_BONDS="no"
    fi
done
if [[ $CONFIGURE_BONDS -eq "yes" ]];
    then
        task_message "Setting slaves for bonds interfaces:"
        echo ""
    for bond in $(seq 1 ${#INTERFACE[@]});
    do
        if [[ ${INT_TYPE[$bond]} == "bond" ]];
        then
            for slave in ${BOND_SLAVES[$bond]};
            do
                dmw_set_slave $slave ${INTERFACE[$bond]}
                if [ $? == 0 ];
                then
                    echo -en "\t$slave on bond$bond"; put_ok
                else
                    echo -en "\t$slave for bond$bond not exists"; put_fail
                fi
            done
        fi
    done
fi
}

function dmw_set_interfaces ()
{
#Configure all the interfaces

for int in $(seq 1 ${#INTERFACE[@]});
do
    if [[ ${INT_TYPE[int]} == "eth" ]];
    then
        dmw_set_int ${INTERFACE[int]} ${IP_INTERFACE[int]} ${NETMASK_INTERFACE[int]}
    elif [[ ${INT_TYPE[int]} == "bond" ]];
    then
        dmw_set_int ${INTERFACE[int]} ${IP_INTERFACE[int]} ${NETMASK_INTERFACE[int]} bond
    fi

    echo "${IP_INTERFACE[int]}  $NAME${HOST_SUFIX[int]}.$DOMAIN $NAME${HOST_SUFIX[int]}">> $HOSTS_FILE
done
}

function dmw_set_routes ()
{
#TODO REVISAR
#Set the routes
task_message "Setting Routes"
if [[ ${#ROUTE_INT[@]} -eq 0 ]]; then
    echo "no routes defined"
    put_ok
    return 1
fi

for route in $(seq 1 ${#ROUTE_DESTINATION[@]});
do
    if [[ -n ${ROUTE_INT[$route]} && -f "$INTERFACES_PATH/ifcfg-${ROUTE_INT[$route]}" ]];
    then
        echo -e "\t${ROUTE_DESTINATION[$route]} via ${ROUTE_GW[$route]} >>  $NET_R_FILE/route-${ROUTE_INT[$route]}"
        if [[ -n ${ROUTE_COMMENT[$route]} ]];
        then
            echo "#${ROUTE_COMMENT[$route]}" >> $NET_R_FILE/route-${ROUTE_INT[$route]};
        fi
        echo "${ROUTE_DESTINATION[$route]} via ${ROUTE_GW[$route]}" >> $NET_R_FILE/route-${ROUTE_INT[$route]}
    fi
done
put_ok;
}

function dmw_add_hosts_entries ()
{
task_message "Setting hosts"
echo $HOST_FILE >> $HOSTS_FILE;
put_ok
}

################## STORAGE FUNCTIONS #################

#Check vol
function dmw_vol_size ()
{
#Take the vol in $1 and the required size on $2
#Returns the new LE size and on the reuturn value
#if must be enlarged (3) or reduced (4).

if [ $# != 2 ];
then
    echo "Missing parameters";
    return 1;
fi
if [ ! -b $1 ];
then
    echo "The lv doesn't exists";
    return 2;
fi

#Size on blocks
size=$($LVDISPLAY -c $1 | cut -d: -f7)
#Logical extents
les=$($LVDISPLAY -c $1 | cut -d: -f8;)

#Size of de vol on MB
size_mb=$(( $size/1024/2 ));
#LE size
le_size_kb=$($VGDISPLAY -c $ROOTVG| cut -d: -f13)
le_size=$(( $le_size_kb / 1024 ))
#Size reuqired in mb
required_size=$(($2*1024))

#LEs required
required_les=$(($required_size/$le_size ))

#Debug
#echo "Size: $size_mb"
#echo "LEs: $les"
#echo "Required size: $required_size"
#echo "Required LEs: $required_les"

#Needs to be enlarger
if [ $required_les -gt $les ];
then
    echo "$required_les"
    return 3;
#Needs to be reduced
elif [ $required_les -lt $les ];
then
    echo $(( $les - $required_les ));
    return 4;
#No needs
elif [ $required_les -eq $les ];
then
    #The $1 lv has the appropiated size;
    echo "$les"
    return 0;
fi
}
function dmw_make_mountpoint ()
{
# $1 lv as /dev/vgxx/lvxx
# $2 mount point path
# $3 fs type


if [ $# -gt 3 ];
then
    return 1;
else
    if [ ! -b $1 ];
    then
        echo -n "The devices $1 doesn't exists!"; put_fail
        return 2;
    fi
    if [ ! -d $2 ];
    then
        mkdir -p $2
    fi
    #If fstype is specify by the user use it
    if [[ ! -z $3 ]];
    then
        FSTYPE=$3;
    fi
    mount -t $3 $1 $2 2>/dev/null 1>&2
    if [[ $? == 0 ]];
    then
        echo "$1    $2    $FSTYPE  defaults    1 3"  >> $FSTAB;
        echo -n "$2 mounted"; put_ok
        return 0
    else
        echo -n "Most probably $1 is not formated on $FSTYPE"; put_fail
        return 3;
    fi
fi
}
function dmw_create_lv ()
{
# $1 lvname
# $2 size in GB
# $3 vgname
vg_size=$(vg_free_gb $3)
if [[ $2 -le $vg_size ]];
then
    task_message "Creating LV $1"
    $LVCREATE -L $2 -n $1 $3 2>/dev/null
    if [ $? == 0 ];
    then
        put_ok;
        return 0;
    else
        put_fail;
        return 1;
    fi
else
    task_message "No available space on $3"
    put_fail;
    return 1
fi
}

function dmw_create_vg ()
{
# $1 vgname
# $2 pvs
task_message "Creating VG $1";

$VGCREATE $1 $2 2>/dev/null 1>&2
if [ $? == 0 ];
then
    put_ok;
    return 0;
else
    put_fail;
    return 1;
fi
}

function dmw_second_vgs ()
{
if [[ $CREATE_OTHERS_VGS == "yes" ]];
then
    task_message "Creating other vgs:"
    echo ""
    for vg_id in $( seq 0 $(( ${#VG_NAME[@]} - 1 )) );
    do
        echo "Making "${VG_NAME[$vg_id]}":"
        disk_list=""
        for disk in ${VG_PVS[$vg_id]};
        do
            echo -e "\tMaking whole disk partition on $disk"
            dmw_make_partition $disk
            disk_list=$disk_list" "$disk"1"
        done
        echo -ne "\t"
        dmw_create_vg ${VG_NAME[$vg_id]} $disk_list
    done
fi
}

function dmw_second_mps ()
{
#Still doesn't support dependencies
if [[ $MAKE_MP == "yes" ]];
then
    task_message "Creating Mount Points"
    echo -e "\n"
    for lv_id in $( seq 0 $(( ${#MP_DIR[@]} - 1 )) );
    do
        create_lv ${MP_LV[$lv_id]} ${MP_SIZE[$lv_id]} ${MP_VG[$lv_id]}
        $MKFS -t $FSTYPE /dev/${MP_VG[$lv_id]}/${MP_LV[$lv_id]} 2>/dev/null 1>&2
        dmw_make_mountpoint /dev/${MP_VG[$lv_id]}/${MP_LV[$lv_id]} ${MP_DIR[$lv_id]} $FSTYPE
    done

fi

}
function dmw_local_fs ()
{
#Resize file systems if needed and is possible
task_message "Resizing FS:"
echo ""
vol_amount=${#VOL_NAME[@]}
vol_index=$(($vol_amount-1))

for vol in $(seq 0 $vol_index);
do
    #Current  free LEs on the VG
    free_les=$(vg_free_pe $ROOTVG)

    $LVDISPLAY /dev/$ROOTVG/${VOL_NAME[vol]} 2>/dev/null 1>&2
	#IF LVEXIST
    if [ $? == 0 ];
    then
        #Current LEs on the LV
        current_les=$($LVDISPLAY -c /dev/$ROOTVG/${VOL_NAME[vol]} | cut -d: -f8)

        #New amount of LEs
        new_les=$(dmw_vol_size /dev/$ROOTVG/${VOL_NAME[vol]} ${VOL_SIZE[vol]})
        #IF VOLSIZE
        if [ $? == 3 ];
        then
            diff_les=$(( $new_les - $current_les ))
			#IF DIFFLES
            if [ $diff_les -lt $free_les ];
            then
                echo -e "\tResizing ${VOL_NAME[vol]}"
                #Corregir - very groncho
                if [ ${VOL_NAME[vol]} == "swapvol" ];
                then
                    $SWAPOFF -a
                fi
                $LVEXTEND -l $new_les /dev/$ROOTVG/${VOL_NAME[vol]} > /dev/null
                $RESIZE /dev/$ROOTVG/${VOL_NAME[vol]} > /dev/null 2>&1
                #Corregir - very groncho
                if [ ${VOL_NAME[vol]} == "swapvol" ];
                then
                    $MKSWAP /dev/$ROOTVG/${VOL_NAME[vol]} 2>/dev/null 1>&2
                    $SWAPON -a
                fi
			#ELSE DIFFLES
            elif [ $? == 2 ];
            then
                dmw_create_lv ${VOL_SIZE[vol]} ${VOL_NAME[vol]}} $ROOTVG
				#IF CREATELV
                if [[ $? == 0 ]];
                then
                    $MKFS -t ${VOL_FS[vol]} /dev/$ROOTVG/${VOL_NAME[vol]} 2>/dev/null
                    dmw_make_mountpoint /dev/$ROOTVG/${VOL_NAME[vol]} ${VOL_MOUNTPOINT[vol]} ${VOL_FS[vol]}
                    if [[ $? == 0 ]]; #IF MOUNTPOINT
                    then
                        task_message "FS ${VOL_NAME[vol]} mounted on ${VOL_MOUNTPOINT[vol]}";
                        put_ok;
                    else #ELSE MOUNTPOINT
                        task_message "${VOL_MOUNTPOINT[vol]} couldn't be created";
                        put_fail;
                    fi #FI MOUNTPOINT
				fi #FI CREATELV
			#ELSE DIFFLES
            else
                echo -e "̣\tNot possible resize ${VOL_NAME[vol]} "
                echo -en "\t\t$diff_les required $free_les available"; put_fail;
	    	fi
		#ELSE VOLSIZE
       else
            echo -e "\t${VOL_NAME[vol]} will not be modified"
       fi #FI VOLSIZE
fi #IF LVEXIST
done
}

############# ALTERNATE DISK Functions #################

function dmw_vrfy_alt ()
{
#Search the vgalt
if [[ $1 = "verbose" ]];
then
	task_message "Searching alternate vg:"
fi
$VGDISPLAY $ALTVG 2>/dev/null 1>&2
if [[ $? == 0 ]];
then
    #Exists
    if [[ $verbose == "yes" ]];
    then
        echo "Found"; put_ok
    fi
    return 0;
else
    #Doesn't Exists
    if [[ $verbose == "yes" ]];
    then
        echo "Not found"; put_fail
    fi
return 1;
fi
}

function dmw_make_partition ()
{
if [ -b $1 ];
then
    if [ -n $2 ]; then size=$2;fi
    size=""
    (echo n; echo p; echo 1; echo ; echo $size; echo w) | fdisk $1 2>/dev/null 1>&2
    if [ $? == 0 ];
    then
        partprobe 2>/dev/null 1>&2
        return 0
    else
        return 1
    fi
else
    return 2
fi
}
function dmw_sync_altvg ()
{
dmw_vrfy_alt 2>/dev/null 1>&2
if [ $? == 0 ];
then
    task_message "Syncronizing alternate (this take a while):"
    #if [ -f $ALTERNATE_FILE ];
    #then
    #    echo "ALTERNATE_EXCLUDE="$ALTERNATE_EXCLUDE >> $ALTERNATE_FILE;
    #fi
    $ALTERNATE -c 2>/dev/null 1>&2
    if [ $? == 0 ];
    then
        put_ok
        return 0
    else
        put_fail
        return 1
    fi
else
    echo -n "Alternate vg not found!"; put_fail
    return 1
fi
}

function dmw_make_altvg ()
{
dmw_vrfy_alt
if [ $? == 1 ];
then
    task_message "Using $ALT_DISK to create alternate vg, will delay some minutes... "
    echo ""
    echo "y" | $ALTERNATE -c -d $ALT_DISK 2>/dev/null 1>&2
    if [[ $? == 0 ]];
    then
        put_ok;
    else
        put_fail;
    fi
else
    task_message "$ALTVG already created!"
    put_ok
fi
}

#### Other tools #####
function clean_udev {
task_message "Deleting udev file"
if [[ -f $UDEV_RULES$UDEV_RULE_NET ]];
then
    rm -f $UDEV_RULES$UDEV_RULE_NET
fi
for file in $(ls $NET_R_FILE/ifcfg-eth*);
do
    sed -ie '/HWADDR/ d' $file
    sed -ie '/UUID/ d' $file
done
put_ok
}

function pre_clone {
task_message "Executing task before clonning:";
echo -e "\n";
dmw_create_secuser;
dmw_set_localtime;
dmw_set_hosts;
dmw_set_ntp;
dmw_set_dns;
dmw_set_snmp;
dmw_add_hosts_entries;
dmw_enable_sarlogin;
dmw_local_fs;
dmw_second_vgs;
#dmw_second_mps;
dmw_root_passwd;
dmw_set_kdump;
dmw_make_altvg;
dmw_disable_selinux;
dmw_set_gateway;

clean_udev;
}

function post_clone {
task_message "Executing task after clonning:";
echo -e "\n"
dmw_set_hostname;
dmw_set_gateway;
dmw_set_bonding;
dmw_set_bonds;
dmw_set_interfaces;
dmw_set_routes;
dmw_disable_rootlogin;
dmw_second_mps;
dmw_sync_altvg;


}

function main {

    clear
    dmw_set_hostname;
    dmw_set_hosts;
    dmw_set_gateway;
    dmw_create_secuser
    dmw_set_localtime;
    dmw_set_mail;
    dmw_set_ntp;
    dmw_set_dns;
    dmw_add_hosts_entries;
    dmw_set_snmp;
    dmw_local_fs;
    dmw_second_vgs;
    dmw_set_kdump;
    dmw_enable_sarlogin;
    dmw_disable_rootlogin;
    dmw_disable_selinux;
    dmw_set_bonding;
    dmw_set_bonds;
    dmw_set_interfaces;
    dmw_set_routes;
    dmw_root_passwd;
    dmw_show_wwns;
    dmw_make_altvg;
    dmw_sync_altvg;

    #dmw_set_multipaths; #for use as interactive function not on build script
}

#main
