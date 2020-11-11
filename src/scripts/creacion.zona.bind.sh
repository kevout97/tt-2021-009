#!/bin/bash
#############################################
#                                           #
#      E.g. Configuración de una zona       #
#                                           #
#############################################

BIND_CONTAINER="bind"

# Creamos la vista para la zona que daremos de alta
cat<<-EOF >> /var/containers/$BIND_CONTAINER/var/named/views/views.conf
view "external-zone" {
    match-clients { any; };
    zone "ck.kevops.xyz" IN {
       type master;
       file "zones/ck.kevops.xyz.zone";
     };
};
EOF

# Creamos el archivo con los registros correspondientes a la zona
cat<<-EOF > /var/containers/$BIND_CONTAINER/var/named/zones/ck.kevops.xyz.zone
\$TTL    3600
@       IN      SOA     ck.kevops.xyz.  . (
                1      ; Serial
                10800   ; Refresh
                3600    ; Retry
                3600    ; Expire
                1)      ; Minimum
                IN NS  ns0
                IN A   34.86.150.228
ns0             IN A   34.86.150.228
jenkins         IN A   34.86.150.228
EOF