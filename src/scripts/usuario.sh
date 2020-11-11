#!/bin/bash

USUARIO="kevin.gomez"
LLAVE="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDTlei6s78ufarao1tuqJF1YQbKof2jpjF3MOomNHGbQ08QWM7c2ivKTC54kSG3hl10hCA4+xj/uktp1JrwspLBbe9rv5BuJZaoRmKYARaeepgAQLvHDXgGlHrbiFrwczm7YtzL9I8V21dJWs2IQbGNbBnEtxikadd5lMpTw3/rtMJGIDbyvKbEu5XAxCwiyuCafdHhIhl+1vxXwb45GuXZHuT9ICAKnf9Ni6s++FsqgaZT0PyfJpN71dyagnv8SgvL8KcCgYcUMiqvsyVTNmQixZGRojuH4Hi2JJyicgpoux+RJtJvgff3EUVzyyXyeqNMP0DLMZDrgH6Uh0a7Q5kQxBzOYkEXNigCN/MtwMyJnttj8h1PpHMdSQrk+wDeI2i1lxCLWUox2W6hnm/LBOG45qyRw8f/WW/NB1HY/RUepMKYtuNl9TRQRaHGgEgs5tYkR6fB2nxmM5dZ2SX+QisHBM4SskcPmN5a40XoSdXe53TiTQ5yFXyqKGwx9GOPk29vK32LCjuijX6LWhJEWyHQk/CivBwnxE/eEZ4X7fI8ukUNNSmYJrBhjgaz2WpaP/6zHAgLN17KovDU4V3tVh7w41RiTa9993pJeTa3DihRXDo110MbCKQpM4PGR2TpXaqfJ2cdHgr1owgOyUPUfi7taGAuVRhUwttFeaQ3LsJ3DQ== kev@localhost.localdomain"

groupadd infraestructura

useradd -m -g infraestructura ${USUARIO} 
mkdir -p /home/${USUARIO}/.ssh/ 
touch /home/${USUARIO}/.ssh/authorized_keys
chmod 700 /home/${USUARIO}/.ssh/
chmod 600 /home/${USUARIO}/.ssh/authorized_keys 
echo "${LLAVE}" > /home/${USUARIO}/.ssh/authorized_keys
chown ${USUARIO}:infraestructura /home/${USUARIO}/ -R 
echo "${USUARIO}  ALL=(ALL)      NOPASSWD: ALL" >> /etc/sudoers