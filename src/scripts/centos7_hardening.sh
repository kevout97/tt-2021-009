#!/bin/bash
### Hardening Script for CentOS 7 Servers.

# ? 
AUDITDIR="/tmp/$(hostname -s)_audit"
TIME="$(date +%F_%T)"
mkdir -p $AUDITDIR
# ? 


echo "##########################################################################################"
echo "PCI-DSS 1.3.3 - Implement anti spoofing measures."
echo "##########################################################################################"

echo "Installing arpwatch..."
yum install -y arpwatch 
sed -i /etc/sysconfig/arpwatch -r -e 's/^options=(.*)/#options=\1/'
echo "options=\"-u arpwatch -n -e - $(/sbin/ip l | grep -oe -e "ens[0-9]+" -e "eth[0-9]+" | sed -e 's/^/-i /'| xargs echo)\"" >> /etc/sysconfig/arpwatch

echo "##########################################################################################"
echo "PCI-DSS Req 2.2.2 - Stopping and disabling unneeded services"
echo "##########################################################################################"

systemctl stop cups
systemctl disable cups
systemctl stop postfix
systemctl disable postfix
systemctl stop abrtd
systemctl disable abrtd
systemctl stop libstoragemgmt.service 
systemctl disable libstoragemgmt.service 
systemctl stop atd
systemctl disable atd
systemctl stop waagent
systemctl disable waagent
systemctl stop tuned
systemctl disable tuned
systemctl stop smartd
systemctl disable smartd
systemctl stop rngd
systemctl disable rngd
systemctl stop rhnsd.service
systemctl disable rhnsd.service


echo "##########################################################################################"
echo "PCI-DSS Req 2.2.3 - Don't install insecure features so you won't have secure them."
echo "##########################################################################################"

echo "##########################################################################################"
echo "PCI-DSS Req Req 2.2.4.b Verify that common security parameter settings are included."
echo "##########################################################################################"

echo "Enable selinux..."
sed -i /etc/sysconfig/selinux -e 's/^SELINUX=.*/SELINUX=enforcing/'
restorecon -R /etc

echo "Setting core dump security limits..."
echo '* hard core 0' > /etc/security/limits.conf

echo "Modifying Network Parameters..."
cp /etc/sysctl.conf $AUDITDIR/sysctl.conf_$TIME.bak

cat > /etc/sysctl.conf << 'EOF'
kernel.dmesg_restrict=1
#kernel.kptr_restrict=2 # dunno
kernel.randomize_va_space=2
kernel.sysrq=0
kernel.yama.ptrace_scope=2
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.forwarding=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.default.log_martians=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.ip_forward=0
net.ipv4.route.flush=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.default.accept_redirects=0
EOF

rm -rf /etc/sysctl.d/*

echo "Disabling IPv6..."
cp /etc/sysconfig/network $AUDITDIR/network_$TIME.bak
echo "NETWORKING_IPV6=no" >> /etc/sysconfig/network
echo "IPV6INIT=no" >> /etc/sysconfig/network
echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6.conf

echo "Restricting Access to the su Command..."
cp /etc/pam.d/su $AUDITDIR/su_$TIME.bak
pam_su='/etc/pam.d/su'
line_num="$(grep -n "^\#auth[[:space:]]*required[[:space:]]*pam_wheel.so[[:space:]]*use_uid" ${pam_su} | cut -d: -f1)"
sed -i "${line_num} a auth		required	pam_wheel.so use_uid" ${pam_su}

echo "Verifying System File Permissions..."
chmod 644 /etc/passwd
chmod 000 /etc/shadow
chmod 000 /etc/gshadow
chmod 644 /etc/group
chown root:root /etc/passwd
chown root:root /etc/shadow
chown root:root /etc/gshadow
chown root:root /etc/group

echo "Searching for world writable files..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 >> $AUDITDIR/world_writable_files_$TIME.log

echo "Searching for Un-owned files and directories..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -ls >> $AUDITDIR/unowned_files_$TIME.log

echo "Searching for Un-grouped files and directories..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup -ls >> $AUDITDIR/ungrouped_files_$TIME.log

echo "Searching for SUID System Executables..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print >> $AUDITDIR/suid_exec_$TIME.log

echo "Searching for SGID System Executables..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 -print >> $AUDITDIR/sgid_exec_$TIME.log

echo "Searching for empty password fields..."
/bin/cat /etc/shadow | /bin/awk -F: '($2 == "" ) { print $1 " does not have a password "}' >> $AUDITDIR/empty_passwd_$TIME.log

echo "Reviewing User and Group Settings..."
echo "Reviewing User and Group Settings..." >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/grep '^+:' /etc/passwd >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/grep '^+:' /etc/shadow >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/grep '^+:' /etc/group >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/cat /etc/passwd | /bin/awk -F: '($3 == 0) { print $1 }' >> $AUDITDIR/reviewusrgrp_$TIME.log

echo "Checking root PATH integrity..."
if [ "`echo $PATH | /bin/grep :: `" != "" ]; then
    echo "Empty Directory in PATH (::)" >> $AUDITDIR/root_path_$TIME.log
fi

if [ "`echo $PATH | /bin/grep :$`"  != "" ]; then
    echo "Trailing : in PATH" >> $AUDITDIR/root_path_$TIME.log
fi

p=`echo $PATH | /bin/sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
while [ "$1" != "" ]; do
    if [ "$1" = "." ]; then
        echo "PATH contains ." >> $AUDITDIR/root_path_$TIME.log
        shift
        continue
    fi
    if [ -d $1 ]; then
        dirperm=`/bin/ls -ldH $1 | /bin/cut -f1 -d" "`
        if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
            echo "Group Write permission set on directory $1" >> $AUDITDIR/root_path_$TIME.log
        fi
        if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
            echo "Other Write permission set on directory $1" >> $AUDITDIR/root_path_$TIME.log
        fi
            dirown=`ls -ldH $1 | awk '{print $3}'`
           if [ "$dirown" != "root" ] ; then
             echo "$1 is not owned by root" >> $AUDITDIR/root_path_$TIME.log
              fi
    else
            echo "$1 is not a directory" >> $AUDITDIR/root_path_$TIME.log
      fi
    shift
done

echo "Checking Permissions on User Home Directories..."
for dir in `/bin/cat /etc/passwd  | /bin/egrep -v '(root|halt|sync|shutdown)' |\
    /bin/awk -F: '($8 == "PS" && $7 != "/sbin/nologin") { print $6 }'`; do
        dirperm=`/bin/ls -ld $dir | /bin/cut -f1 -d" "`
        if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
            echo "Group Write permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log
        fi
        if [ `echo $dirperm | /bin/cut -c8 ` != "-" ]; then
            echo "Other Read permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log

        fi

        if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
            echo "Other Write permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log
        fi
        if [ `echo $dirperm | /bin/cut -c10 ` != "-" ]; then
            echo "Other Execute permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log
        fi
done

echo "Checking User Dot File Permissions..."
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |
/bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.[A-Za-z0-9]*; do

        if [ ! -h "$file" -a -f "$file" ]; then
            fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`

            if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]; then
                echo "Group Write permission set on file $file" >> $AUDITDIR/dotfile_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]; then
                echo "Other Write permission set on file $file" >> $AUDITDIR/dotfile_permission_$TIME.log
            fi
        fi

    done

done

echo "Checking Permissions on User .netrc Files..."
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |\
    /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.netrc; do
        if [ ! -h "$file" -a -f "$file" ]; then
            fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`
            if [ `echo $fileperm | /bin/cut -c5 ` != "-" ]
            then
                echo "Group Read set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]
            then
                echo "Group Write set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c7 ` != "-" ]
            then
                echo "Group Execute set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c8 ` != "-" ]
            then
                echo "Other Read  set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]
            then
                echo "Other Write set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c10 ` != "-" ]
            then
                echo "Other Execute set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
        fi
    done
done

echo "Checking for Presence of User .rhosts Files..."
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' |\
    /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.rhosts; do
        if [ ! -h "$file" -a -f "$file" ]; then
            echo ".rhosts file in $dir" >> $AUDITDIR/rhosts_$TIME.log
        fi    done
done

echo "Checking Groups in /etc/passwd..."

for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
  grep -q -P "^.*?:x:$i:" /etc/group
  if [ $? -ne 0 ]; then
    echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group" >> $AUDITDIR/audit_$TIME.log
  fi
done

echo "Checking That Users Are Assigned Home Directories..."

cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
  if [ $uid -ge 500 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
 echo "The home directory ($dir) of user $user does not exist." >> $AUDITDIR/audit_$TIME.log
 fi
done

echo "Checking That Defined Home Directories Exist..."

cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
 if [ $uid -ge 500 -a -d "$dir" -a $user != "nfsnobody" ]; then
 owner=$(stat -L -c "%U" "$dir")
 if [ "$owner" != "$user" ]; then
 echo "The home directory ($dir) of user $user is owned by $owner." >> $AUDITDIR/audit_$TIME.log
 fi
 fi
done

echo "Configuring Cron and Anacron..."
yum -y install cronie-anacron >> $AUDITDIR/service_install_$TIME.log
systemctl enable crond
chown root:root /etc/anacrontab
chmod og-rwx /etc/anacrontab
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
touch /etc/cron.deny
chown root:root /etc/cron.deny
chmod og-rwx /etc/cron.deny
touch /var/run/wpa_supplicant
chown root:root /var/run/wpa_supplicant
chmod og-rwx /var/run/wpa_supplicant

echo "##########################################################################################"
echo "PCI-DSS-Req 2.2.5 - disable unnecesary drivers"
echo "##########################################################################################"

echo "Disabling Legacy Filesystems"
cat > /etc/modprobe.d/CIS.conf << "EOF"
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squahfs /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install vfat /bin/true
EOF

echo "blacklist firewire-core" > /etc/modprobe.d/blacklist-firewire.conf
echo "blacklist usb-storage" > /etc/modprobe.d/blacklist.conf

echo "Removing GCC compiler..."
yum -y remove gcc*
yum -y remove cpp
echo "Removing legacy/unneeded services..."
yum -y remove rsh-server rsh ypserv tftp tftp-server talk talk-server telnet-server >> $AUDITDIR/service_remove_$TIME.log
echo "Disabling LDAP..."
yum -y remove openldap-servers >> $AUDITDIR/service_remove_$TIME.log
yum -y remove openldap-clients >> $AUDITDIR/service_remove_$TIME.log
echo "Disabling DNS..."
yum -y remove bind >> $AUDITDIR/service_remove_$TIME.log
echo "Disabling FTP Server..."
yum -y remove vsftpd >> $AUDITDIR/service_remove_$TIME.log
echo "Disabling Dovecot..."
yum -y remove dovecot >> $AUDITDIR/service_remove_$TIME.log
echo "Disabling Samba..."
yum -y remove samba >> $AUDITDIR/service_remove_$TIME.log
echo "Disabling SNMP..."
yum -y remove net-snmp >> $AUDITDIR/service_remove_$TIME.log
echo "Setting Daemon umask..."
cp /etc/init.d/functions $AUDITDIR/functions_$TIME.bak
echo "umask 027" >> /etc/init.d/functions

echo "##########################################################################################"
echo "PCI-DSS 6.2.a+ - Installation of applicable critical vendor-supplied security patches within 
      one month of release."
echo "##########################################################################################"
echo "Updating system up to `date` packages"
yum update -y
grep -q 'yum.*update.*security' /etc/crontab || echo '59 4 * * 1,3,5,7  root /usr/bin/yum -y update --security' >> /etc/crontab

echo "##########################################################################################"
echo "PCI-DSS Req 8.1.8 - Set 15 minutes inactivity timeout"
echo "##########################################################################################"

echo "Backup pam.d dir"
tar czf ${AUDITDIR}/pam.tar.gz /etc/pam.d/

echo "##########################################################################################"
echo "PCI-DSS 8.2.1 - Strong hashing algorithm"
echo "##########################################################################################"
echo "Upgrading password hashing algorithm to SHA512..."
authconfig --passalgo=sha512 --update

echo "##########################################################################################"
echo "PCI-DSS Req 8.2.3+ - Strong passwords, min 7 chars, alpha-num"
echo "##########################################################################################"

authconfig --passminlen=7 --passminclass=4 --enablereqlower --enablerequpper --enablereqdigit --enablereqother --update 

echo "##########################################################################################"
echo "PCI-DSS Req 8.1.6 - Lock account after 6 failed attempts"
echo "        Req 8.1.7+ - Set at least 30 minutes lock out"
echo "##########################################################################################"

authconfig --enablefaillock --faillockargs="deny=6 unlock_time=7200 fail_interval=3600"  --update

echo "##########################################################################################"
echo "PCI-DSS Req-8.2.3 - Remove nullok"
echo "##########################################################################################"

sed --follow-symlinks -i 's/\<nullok\>//g' /etc/pam.d/system-auth
sed --follow-symlinks -i 's/\<nullok\>//g' /etc/pam.d/password-auth

# 2020-02-12 authconfig --enablefaillock is not working as expected, adding hardcoded values
#                       https://bugzilla.redhat.com/show_bug.cgi?id=1271804#c3
echo 'H4sIADB3RF4AA+1WwY6bMBDNOV9hadVjUkgI20Op1A+o1EN7WlXIaw/BCtjUNsny9x0TloaQLKtqtd1Wfofg4Ofx8/DsMVj2vqLlkuOvMQel+YLWNl9QNnsxBIg4iton4vy52oTBLFzHqzCI4s0mngVhFEXhjAQvJ+E6amOpJmSmlbJP8ab6/1HcvPv6+csiXAbzG/ItF4ZkogCCT3SBWmxBgqYW+BK7vxvQhOVUbsGQgygKcg+Eg7FaNcCJzYFIeLDEihLc8JwpmYmtC6ZruZy7V6SDhp+10DiqBRowBblfGjUmGWGhJ2UUp1Vsh0xSaWjJtObCEoOypUU5skliUkvHSp2S5HYVBMQNTIW0oPe0SNYxvoI9yNTxU/dpiftJT8eFAy2mzjLBhJuj01JL8eB0WN2kmdDGpm4HDQbdcchoXdiEC/gxWoBjuv/dCq5In8iIqRkD4KnIXMhacPIpISHuKoJMsMf+M1nj5Lu5XfbnlDFVH9c4kf4xdRCxy86ANc4hBqNFjb6apo4X+vFknRNqKtClsOeTjHknC5zPHw/Ey7lgmrJdIe7HFkAyvkg2pBQSTZl8cA1WYE+yJiV9SDVUQG0SEi4ytUMiZ6hCuDd13yr6lupbOLgfuwWmDMuB7VojWYWeaSpIBrKvu9bkdBOu3IOrw/kC8IukXdBxFi4bx6DJhJJth6osNmnxm7aDRsj2A2CMvdrBgD8OWwj8XMYFXjwd2DTGQskd85R419ne5bjbgmIrle524dBLaL+9YHjoScK0kvzoqDYJaLMJpY8+/9vn+J8C+vp/TOXLV/9n1P846ur/7TrcrFz9D1eRr/+vgTdf/6+dz3397yr/k0X0Qv2fqO5ZpZHOzyW90jVg89auAb62v7naPpZdHXADW6Wbi7pLKO9BO2t11f2suPu7gr8reHh4eHh4eHh4eHh4eHh4eHh4eHh4eHj8D/gFi4Pr0AAoAAA=' | base64 -w0 -d | tar xz -C / 


echo "##########################################################################################"
echo "PCI-DSS 10.x Track and monitor all access to network resources and cardholder data."
echo "##########################################################################################"


echo "##########################################################################################"
echo "PCI-DSS 10.4.1.a Examine the process for acquiring, distributing and
storing the correct time within the organization to verify that:
• Only the designated central time server(s) receives time
signals from external sources, and time signals from external
sources are based on International Atomic Time or UTC.
• Where there is more than one designated time server, the
time servers peer with one another to keep accurate time,
• Systems receive time information only from designated
central time server(s)."
echo "##########################################################################################"

echo "Ensure chrony installation."
yum install -y chrony 
echo "Ensure official ntp servers."

sed -i /etc/chrony.conf -r -e 's/server(.*)/#server\1 #orig/' -e 's/^pool(.*)/#pool\1 #orig/' -e '3i server 2.rhel.pool.ntp.org ibrust\nserver 3.rhel.pool.ntp.org iburst\nserver 0.rhel.pool.ntp.org iburst\nserver 1.rhel.pool.ntp.org iburst'

echo "##########################################################################################"
echo "PCI-DSS Req 10.4.2.a verify that access to time data is restricted to only personnel with a business need to access time data."
echo "##########################################################################################"

chown root:root /etc/chrony.conf
chmod 600 /etc/chrony.conf

echo "##########################################################################################"
echo "PCI-DSS Req 10.5.2 - Protect audit trail files from unauthorized modifications."
echo "##########################################################################################"

chown -R root:root /var/log/audit/
chmod 700 /var/log/audit/ 
chmod 600 /var/log/audit/*

echo "Enabling auditd service..."
systemctl enable auditd

echo "Configuring Audit Log Storage Size..."
cp -a /etc/audit/auditd.conf /etc/audit/auditd.conf.bak
sed -i  /etc/audit/auditd.conf -e "s%max_log_file_action =.*%max_log_file_action = rotate%" 
sed -i  /etc/audit/auditd.conf -e "s%max_log_file =.*%max_log_file = 32%" 
sed -i  /etc/audit/auditd.conf -e "s%space_left_action =.*%space_left_action = email%"
sed -i  /etc/audit/auditd.conf -e "s%admin_space_left_action =.*%admin_space_left_action = halt%"

echo "Configuring Audit Rules..."
cat > /etc/audit/rules.d/audit.rules  << 'EOF'
# AMX AUDIT RULES
# Remove any existing rules
-D
# Increase kernel buffer size
-b 16384

## Ignore SELinux AVC records
#-a always,exclude -F msgtype=AVC ?

## Ignore current working directory records
-a always,exclude -F msgtype=CWD

## Ignore EOE records (End Of Event, not needed)
-a always,exclude -F msgtype=EOE

## Cron jobs fill the logs with stuff we normally don't want (works with SELinux)
-a never,user -F subj_type=crond_t
-a exit,never -F subj_type=crond_t

## This prevents chrony from overwhelming the logs
-a never,exit -F arch=b64 -S adjtimex -F auid=unset -F uid=chrony -F subj_type=chronyd_t

## This is not very interesting and wastes a lot of space if the server is public facing
#-a always,exclude -F msgtype=CRYPTO_KEY_USER ?

## VMWare tools
-a exit,never -F arch=b32 -S fork -F success=0 -F path=/usr/lib/vmware-tools -F subj_type=initrc_t -F exit=-2
-a exit,never -F arch=b64 -S fork -F success=0 -F path=/usr/lib/vmware-tools -F subj_type=initrc_t -F exit=-2

# Watch syslog configuration 
-w /etc/rsyslog.conf
-w /etc/rsyslog.d/
# Watch PAM and authentication configuration
-w /etc/pam.d/
-w /etc/nsswitch.conf
# Watch system log files
-w /var/log/messages
-w /var/log/audit/audit.log
-w /var/log/audit/audit[1-4].log
# Watch audit configuration files
-w /etc/audit/auditd.conf -p wa
-w /etc/audit/audit.rules -p wa
# Watch login configuration
-w /etc/login.defs
-w /etc/securetty
-w /etc/resolv.conf
# Watch cron and at
-w /etc/at.allow
-w /etc/at.deny
-w /var/spool/at/
-w /etc/crontab
-w /etc/anacrontab
-w /etc/cron.allow
-w /etc/cron.deny
-w /etc/cron.d/
-w /etc/cron.hourly/
-w /etc/cron.weekly/
-w /etc/cron.monthly/
# Watch shell configuration
-w /etc/profile.d/
-w /etc/profile
-w /etc/shells
-w /etc/bashrc
-w /etc/csh.cshrc
-w /etc/csh.login
# Watch kernel configuration
-w /etc/sysctl.conf
-w /etc/modprobe.conf
# Watch linked libraries
-w /etc/ld.so.conf -p wa
-w /etc/ld.so.conf.d/ -p wa
# Watch init configuration
-w /etc/rc.d/init.d/
-w /etc/sysconfig/
-w /etc/inittab -p wa
-w /etc/rc.local
-w /usr/lib/systemd/
-w /etc/systemd/
# Watch filesystem and NFS exports
-w /etc/fstab
-w /etc/exports
# Watch xinetd configuration
-w /etc/xinetd.conf
-w /etc/xinetd.d/
# Watch Grub2 configuration
-w /etc/grub2.cfg
-w /etc/grub.d/
# Watch TCP_WRAPPERS configuration
-w /etc/hosts.allow
-w /etc/hosts.deny
# Watch sshd configuration
-w /etc/ssh/sshd_config
# Audit system events
-a always,exit -F arch=b32 -S acct -S reboot -S sched_setparam -S sched_setscheduler -S setrlimit -S swapon
-a always,exit -F arch=b64 -S acct -S reboot -S sched_setparam -S sched_setscheduler -S setrlimit -S swapon
# Audit any link creation
-a always,exit -F arch=b32 -S link -S symlink
-a always,exit -F arch=b64 -S link -S symlink
##############################
## NIST 800-53 Requirements ##
##############################
# 2.6.2.4.1 Records Events that Modify Date and Time Information
# PCI-DSS 10.4, 10.4.2
-a always,exit -F arch=b32 -S adjtimex,settimeofday,stime -F subj_type!=ntpd_t -F key=time-change
-a always,exit -F arch=b64 -S adjtimex,settimeofday -F subj_type!=ntpd_t -F key=time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -F subj_type!=ntpd_t -F key=time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -F subj_type!=ntpd_t -F key=time-change
-w /etc/localtime -p wa -k time-change
# 2.6.2.4.2 Record Events that Modify User/Group Information
# PCI-DSS 10.2.5.c 
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
#2.6.2.4.3 Record Events that Modify the Systems Network Environment
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k audit_network_modifications
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k audit_network_modifications
-w /etc/issue -p wa -k audit_network_modifications
-w /etc/issue.net -p wa -k audit_network_modifications
-w /etc/hosts -p wa -k audit_network_modifications
-w /etc/sysconfig/network -p wa -k audit_network_modifications
#2.6.2.4.4 Record Events that Modify the System Mandatory Access Controls
-w /etc/selinux/ -p wa -k MAC-policy
#2.6.2.4.5 Ensure auditd Collects Logon and Logout Events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock -p wa -k logins
#2.6.2.4.6 Ensure auditd Collects Process and Session Initiation Information
-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session
#2.6.2.4.12 Ensure auditd Collects System Administrator Actions
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
#2.6.2.4.13 Make the auditd Configuration Immutable
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b32 -S init_module,finit_module,create_module,delete_module -F key=modules
-a always,exit -F arch=b64 -S init_module,finit_module,create_module,delete_module -F key=modules
# Ignore all the anonymous events. Often tagged on every rule, but ignoring
# up front should improve processing time
-a exit,never -F auid=4294967295
# Ignore system services
-a exit,never -F auid<1000
#2.6.2.4.7 Ensure auditd Collects Discretionary Access Control Permission Modification Events
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -k perm_mod
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -k perm_mod
# 2.6.2.4.8 Ensure auditd Collects Unauthorized Access Attempts to Files (unsuccessful)
# Req-10.2.1
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -k access
#2.6.2.4.9 Ensure auditd Collects Information on the Use of Privileged Commands
-a always,exit -F path=/usr/sbin/semanage -F perm=x -F key=privileged-priv_change
-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F key=privileged-priv_change
-a always,exit -F path=/usr/bin/chcon -F perm=x -F key=privileged-priv_change
-a always,exit -F path=/usr/sbin/restorecon -F perm=x -F key=privileged-priv_change
-a always,exit -F path=/usr/bin/userhelper -F perm=x -F key=privileged
-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F key=privileged
-a always,exit -F path=/usr/libexec/pt_chown -F perm=x -F key=privileged
## NESSUS RULES
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/sysconfig/network-scripts/ -p wa -k system-locale
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy
-w /var/log/lastlog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-w /var/run/wtmp -p wa -k logins
-w /var/run/btmp -p wa -k logins
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/sudo.log -p wa -k actions
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/sysconfig/network-scripts/ -p wa -k system-locale
# 
-a always,exit -F arch=b32 -S rmdir,unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S rmdir,unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -F key=delete
# 10.2.2 Audit all actions by any individual with root or administrative privileges
-a exit,always -F arch=b64 -F euid=0 -S execve -k root-commands
-a exit,always -F arch=b32 -F euid=0 -S execve -k root-commands
EOF
# ? 
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged"}' >> /etc/audit/rules.d/audit.rules
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"}' >> /etc/audit/rules.d/audit.rules

echo "##########################################################################################"
echo "PCI-DSS 10.5.2 Protect audit trail files from unauthorized modifications."
echo "##########################################################################################"
echo '-e 2' >> /etc/audit/rules.d/audit.rules

echo "##########################################################################################"
echo "PCI-DSS 10.5.5 - Implement File Integrity Software"
echo "##########################################################################################"
echo "Installing File Integrity Checker AIDE and SCAP scanner"
yum install -y aide openscap-scanner

echo "Building file integrity db"
if [ ! -f /var/lib/aide/aide.db.gz ]; then
    /usr/sbin/aide --init
    mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
fi

if ! grep -q /usr/sbin/aide /etc/crontab; then
    # run every day at 05:59 one file integrity check
    echo '59 5 * * * root /usr/sbin/aide --check' >> /etc/crontab
fi

echo "Creating Banner..."
sed -i /etc/ssh/sshd_config -e "s%#Banner.*%Banner \/etc\/issue\.net%"
sed -i /etc/ssh/sshd_config -e "s%Banner.*%Banner \/etc\/issue\.net%"
cp -p /etc/issue.net $AUDITDIR/issue.net_$TIME.bak
cat > /etc/issue.net << 'EOF'
*------------------------------------------------------------------------*
|                                                                        |
| Esta máquina virtual así como la información que procesa, almacena     |
| o transfiere  es propiedad privada de LA EMPRESA.                      |
|                                                                        |
| Por lo anterior, toda actividad es vigilada, monitoreada, grabada,     |
| respaldada e inspeccionada.                                            |
|                                                                        |
| El usuario que procesa información a través del Sistema acepta el      |
| tratamiento y uso de la información y se compromete a respetar los     |
| términos y políticas de seguridad de la información.                   |
|                                                                        |
| Cualquier acción no autorizada o inapropiada puede resultar en         |
| procedimientos legales contra el usuario así como en actas             |
| administrativas o cualquier otro medio de penalización contemplado en  |
| la legislación vigente.                                                |
|                                                                        |
| Por lo anterior, si no está de acuerdo, favor de CERRAR SESIÓN.        |
*------------------------------------------------------------------------*
EOF
cp -p /etc/motd /etc/motd_$TIME.bak
cat > /etc/motd << 'EOF'
2020-02-07 | SÓLO USO AUTORIZADO
EOF

echo "##########################################################################################"
echo "PCI-DSS Req 8.2.4 - Change user pssword every 90 days"
echo "##########################################################################################"
echo "Setup new account creation defaults"
grep -q '^PASS_MAX_DAYS' /etc/login.defs && sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs \
	|| echo 'PASS_MAX_DAYS 90' >> /etc/login.defs
grep -q '^PASS_MIN_DAYS' /etc/login.defs && sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs \
	|| echo 'PASS_MIN_DAYS 0' >> /etc/login.defs
grep -q '^PASS_MIN_LEN' /etc/login.defs && sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 7/' /etc/login.defs \
	|| echo 'PASS_MIN_LEN 7' >> /etc/login.defs
grep -q '^PASS_WARN_AGE' /etc/login.defs && sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 10/' /etc/login.defs \
	|| echo 'PASS_WARN_AGE 10' >> /etc/login.defs

echo "Set 90 days user expiration password 4 existing non sys users..."
cat /etc/passwd | awk -F: ' { if(int($3)>1000) {print "chage -M 90 -I 0 -W 10 "$1}}' | sh

echo "##########################################################################################"
echo "PCI-DSS 8.2 - Assign users an exclusive id"
echo "##########################################################################################"

echo "Checking for Duplicate UIDs..."
/bin/cat /etc/passwd | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        users=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 \
            /etc/passwd | /usr/bin/xargs`
        echo "Duplicate UID ($2): ${users}" >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking for Duplicate GIDs..."
/bin/cat /etc/group | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        grps=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 \
            /etc/group | xargs`
        echo "Duplicate GID ($2): ${grps}" >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking That Reserved UIDs Are Assigned to System Accounts..."

defUsers="root bin daemon adm lp sync shutdown halt mail news uucp operator games
gopher ftp nscd vcsa rpc mailnull smmsp pcap ntp dbus avahi sshd rpcuser
nfsnobody haldaemon avahi-autoipd distcache apache oprofile webalizer dovecot squid
named xfs gdm sabayon usbmuxd rtkit abrt saslauth pulse postfix tcpdump chrony"
/bin/cat /etc/passwd | /bin/awk -F: '($3 < 1000) { print $1" "$3 }' |\
    while read user uid; do
        found=0
        for tUser in ${defUsers}
        do
            if [ ${user} = ${tUser} ]; then
                found=1
            fi
        done
        if [ $found -eq 0 ]; then
            echo "User $user has a reserved UID ($uid)."  >> $AUDITDIR/audit_$TIME.log
        fi
    done

echo "Checking for Duplicate User Names..."
cat /etc/passwd | cut -f1 -d":" | sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        uids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \
            /etc/passwd | xargs`
        echo "Duplicate User Name ($2): ${uids}"  >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking for Duplicate Group Names..."
cat /etc/group | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        gids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \
            /etc/group | xargs`
        echo "Duplicate Group Name ($2): ${gids}"  >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking for Presence of User .netrc Files..."
for dir in `/bin/cat /etc/passwd |\
    /bin/awk -F: '{ print $6 }'`; do
    if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
        echo ".netrc file $dir/.netrc exists"  >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking for Presence of User .forward Files..."
for dir in `/bin/cat /etc/passwd |\
    /bin/awk -F: '{ print $6 }'`; do
    if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
        echo ".forward file $dir/.forward exists"  >> $AUDITDIR/audit_$TIME.log
    fi
done


echo ""
echo "Successfully Completed"
echo "Please check $AUDITDIR"