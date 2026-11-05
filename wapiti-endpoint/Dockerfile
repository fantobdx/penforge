FROM php:8.2-apache

RUN a2enmod rewrite

COPY . /var/www/html/

RUN chown -R www-data:www-data /var/www/html \
 && chmod -R 755 /var/www/html

RUN echo '<Directory /var/www/html>\n    AllowOverride All\n</Directory>' \
    >> /etc/apache2/apache2.conf

EXPOSE 80
