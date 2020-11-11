#!/bin/bash
#######################################################################
#                                                                     #
#                        RUN NGINX CONTAINER                          #
#                                                                     #
#######################################################################
firewall-cmd --permanent --add-port=80/tcp
firewall-cmd --permanent --add-port=443/tcp
firewall-cmd --reload

NGINX_CONTAINER="nginx"

# Create base directories
mkdir -p /var/containers/shared/var/www/sites \
        /var/containers/$NGINX_CONTAINER/{var/log/nginx,etc/nginx/vhosts,etc/nginx/conf.d,var/cache/nginx,var/backups,etc/nginx/keys}
# Create soft link
ln -s /var/containers/$NGINX_CONTAINER/var/log/nginx/ /var/log/
# Setup logrotate script
mkdir -p /etc/logrotate.d/

echo 'L3Zhci9sb2cvbmdpbngvKi5sb2cgewogICAgICAgIGRhaWx5CiAgICAgICAgbWlzc2luZ29rCiAgICAgICAgcm90YXRlIDYwCiAgICAgICAgY29tcHJlc3MKICAgICAgICBkZWxheWNvbXByZXNzCiAgICAgICAgbm90aWZlbXB0eQogICAgICAgIGNyZWF0ZSA2NDQKICAgICAgICBzaGFyZWRzY3JpcHRzCiAgICAgICAgcG9zdHJvdGF0ZQogICAgICAgICAgICBuZ2lueCAtcyByZWxvYWQKICAgICAgICBlbmRzY3JpcHQKfQovdmFyL2xvZy9uZ2lueC8qLyoubG9nIHsKICAgICAgICBkYWlseQogICAgICAgIG1pc3NpbmdvawogICAgICAgIHJvdGF0ZSA2MAogICAgICAgIGNvbXByZXNzCiAgICAgICAgZGVsYXljb21wcmVzcwogICAgICAgIG5vdGlmZW1wdHkKICAgICAgICBjcmVhdGUgNjQ0CiAgICAgICAgc2hhcmVkc2NyaXB0cwogICAgICAgIHBvc3Ryb3RhdGUKICAgICAgICAgICAgbmdpbnggLXMgcmVsb2FkCiAgICAgICAgZW5kc2NyaXB0Cn0KCg==' | base64 -w0 -d > /etc/logrotate.d/$NGINX_CONTAINER

cat<<-EOF >
user  nginx;
worker_processes  1;

#error_log  /dev/stdout warn;
pid        /var/run/nginx.pid;


events {
    worker_connections  102400;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    server_tokens off;

    #access_log  /dev/null;

    sendfile        on;
    tcp_nopush      on;
    tcp_nodelay     on;

    server_names_hash_bucket_size   128;
    # Start: Size Limits & Buffer Overflows #
    client_body_buffer_size         1K;
    client_header_buffer_size       1k;
    client_max_body_size            64k;
    large_client_header_buffers     16 16k;
    # END: Size Limits & Buffer Overflows #

    # Default timeouts
    keepalive_timeout          305s;
    client_body_timeout         10s;
    client_header_timeout       10s;
    send_timeout                20s;
    fastcgi_connect_timeout     60s;
    fastcgi_send_timeout        30s;
    fastcgi_read_timeout        60s;
    #
    reset_timedout_connection   on;

    gzip  on;
    gzip_disable "msie6";
    gzip_http_version 1.1;
    gzip_buffers 32 8k;
    gzip_min_length  1000;
    gzip_types  text/plain   
            text/css
            text/javascript
            text/xml
            text/x-component
            application/javascript
            application/json
            application/xml
            application/rss+xml
            font/truetype
            font/opentype
            application/vnd.ms-fontobject
            image/svg+xml
            image/png
            image/gif
            image/jpeg
            image/jpg;
    proxy_intercept_errors  off;

    include conf.d/*.conf;
    include vhosts/*.conf;
}
stream {
    include stream.d/*.conf;
}
EOF

docker run -td --name $NGINX_CONTAINER \
    -p 80:80 \
    -p 443:443 \
    -v /var/containers/shared/var/www/sites:/var/www/sites:z \
    -v /var/containers/$NGINX_CONTAINER/var/log/nginx:/var/log/nginx:z \
    -v /var/containers/$NGINX_CONTAINER/etc/nginx/vhosts:/etc/nginx/vhosts:z \
    -v /var/containers/$NGINX_CONTAINER/etc/nginx/stream.d:/etc/nginx/stream.d:z \
    -v /var/containers/$NGINX_CONTAINER/etc/nginx/certs:/etc/nginx/certs:z \
    -v /var/containers/$NGINX_CONTAINER/var/cache/nginx:/var/cache/nginx:z  \
    -v /var/containers/$NGINX_CONTAINER/var/backups:/var/backups:z \
    -v /etc/localtime:/etc/localtime:ro \
    --hostname=nginx.service \
    --ulimit nofile=1024600:1024600 \
    --sysctl net.core.somaxconn=65535 \
    --restart always \
    nginx:stable
