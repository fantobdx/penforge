# syntax=docker/dockerfile:1
FROM alpine:3.21

RUN apk add --no-cache apache2 php83 php83-apache2 && \
    sed -i '/mod_rewrite.so/s/^#\s*//' /etc/apache2/httpd.conf && \
    sed -i 's|/var/www/localhost/htdocs|/var/www/html|g' /etc/apache2/httpd.conf && \
    sed -i 's|AllowOverride None|AllowOverride All|g' /etc/apache2/httpd.conf && \
    mkdir -p /var/www/html /run/apache2

COPY . /var/www/html/

RUN chown -R apache:apache /var/www/html && \
    chmod -R 755 /var/www/html

EXPOSE 80

CMD ["httpd", "-D", "FOREGROUND"]
