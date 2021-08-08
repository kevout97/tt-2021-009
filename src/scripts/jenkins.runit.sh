#!/bin/bash
###############################
#                             #
#       Jenkins runit         #
#                             #
###############################

firewall-cmd --permanent --add-port=50000/tcp
firewall-cmd --reload
JENKINS_HOST_PORT=8080
firewall-cmd --permanent --add-port=$JENKINS_HOST_PORT/tcp
firewall-cmd --reload


JENKINS_CONTAINER=jenkins

mkdir -p /var/containers/$JENKINS_CONTAINER/var/jenkins_home

chown 1000:1000 -R /var/containers/$JENKINS_CONTAINER

docker run -itd --name $JENKINS_CONTAINER \
  --restart always \
  -p $JENKINS_HOST_PORT:8080 \
  -p 50000:50000 \
  -v /etc/localtime:/etc/localtime:ro \
  -v /usr/share/zoneinfo:/usr/share/zoneinfo:ro \
  -v /var/containers/$JENKINS_CONTAINER/var/jenkins_home:/var/jenkins_home:z \
  -e TZ=America/Mexico_City \
  jenkins/jenkins:lts
