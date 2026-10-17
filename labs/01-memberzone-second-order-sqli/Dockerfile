FROM php:8.2-cli
RUN apt-get update && apt-get install -y libsqlite3-dev && rm -rf /var/lib/apt/lists/* \
    && docker-php-ext-install pdo_sqlite
WORKDIR /app
COPY src/ /app/
EXPOSE 80
CMD ["php", "-S", "0.0.0.0:80", "-t", "/app"]
