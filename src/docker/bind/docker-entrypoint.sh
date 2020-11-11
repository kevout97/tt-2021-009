#!/bin/bash

FIRST_RUN=1
MAIN_PROC_RUN=1
BIND_CONFIG_FILE="/etc/named/named.conf"
BIND_CONFIG_FILE_BCK="/etc/named.conf.back"

trap "docker_stop" SIGINT SIGTERM

if [ -z "${BIND_KEY_ALGORITHM}" ]; then
        BIND_KEY_ALGORITHM="hmac-md5"
    fi

if [ -z "${BIND_CPU}" ]; then
    BIND_CPU=1
fi

HOSTNAME=$(cat /etc/hostname | awk -F. '{print $1}')
VERIFY_DNSSEC=$(cat /etc/rndc.key | grep $HOSTNAME -o)
if [ -z ${VERIFY_DNSSEC} ]; then
    KEY_FILE=$(dnssec-keygen -a ${BIND_KEY_ALGORITHM} -b 512 -n HOST ${HOSTNAME})
    PRIV_KEY=$(cat ${KEY_FILE}.private | awk '/Key/{print $2}')
    sed -i /etc/rndc.key -e "s/key-name/${HOSTNAME}/" -e "s/key-algorithm/${BIND_KEY_ALGORITHM}/" -e "s#key-value#${PRIV_KEY}#"
fi

function docker_stop {
    echo "[BIND $(date +'%Y-%m-%d %R')] Rcv end signal"
    BIND_PID=$(pgrep named)
    rndc stop > /dev/null 2>&1 || kill -TERM $BIND_PID
    export MAIN_PROC_RUN=0
}

function check_files(){
    if [ ! -f "/var/named/views/views.conf" ]; then
        touch /var/named/views/views.conf
    fi

    if [ ! -f "/etc/named/named.conf" ]; then
        mkdir -p /etc/named/
        cp $BIND_CONFIG_FILE_BCK /etc/named.conf
    fi
}

check_files
echo "[BIND $(date +'%Y-%m-%d %R')] Starting Bind"
while [ ${MAIN_PROC_RUN} -eq 1 ]; do
    if [ "${FIRST_RUN}" -ne 0 ] ; then
        /usr/sbin/named -4 -u named -c $BIND_CONFIG_FILE -d 0 -g -n $BIND_CPU
    fi
    sleep 15
    /sbin/docker-health-check.sh
    FIRST_RUN=$?
done