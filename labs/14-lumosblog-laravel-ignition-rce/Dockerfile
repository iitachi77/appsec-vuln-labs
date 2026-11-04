# LumosBlog — Laravel 8 with facade/ignition 2.5.1 (vulnerable to CVE-2021-3129) and
# APP_DEBUG=true. Educational lab.
#
# NOTE: built for your Ubuntu box. I could NOT pre-test it (no PHP/Composer here, Docker
# daemon down), so this is a first-run-together lab — if composer version resolution or a
# PHP extension trips the build, send me the error and I'll correct it.

FROM php:8.0-cli

# PHP extensions Laravel actually needs here (dropped gd/intl — they pull ICU/image libs
# and aren't required by Laravel core; that was the exit-100 culprit).
COPY --from=mlocati/php-extension-installer:latest /usr/bin/install-php-extensions /usr/local/bin/
RUN install-php-extensions pdo_sqlite mbstring zip bcmath

# git/unzip for composer, with an apt retry loop for flaky mirrors (the exit-100 cause).
RUN for i in 1 2 3 4 5; do apt-get update && break || sleep 5; done \
    && apt-get install -y --no-install-recommends git unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Composer from the official image (no curl download needed).
COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer

WORKDIR /app

# Laravel 8 skeleton, then FORCE the vulnerable Ignition version.
# facade/ignition was patched in 2.5.2 — pinning 2.5.1 reintroduces CVE-2021-3129.
# (This pin is the dependency root-cause you're meant to find in the code-review half.)
# Composer 2.8+ blocks advisory-flagged packages by default (it does SCA now!). This lab is
# DELIBERATELY vulnerable (EOL Laravel 8 + the vulnerable ignition), so disable that policy
# for the build only. In the real world, that block is exactly what should stop this shipping.
RUN composer config -g policy.advisories.block false \
    && composer create-project laravel/laravel:^8.0 . --prefer-dist --no-interaction \
    && composer require "facade/ignition:2.5.1" --with-all-dependencies --no-interaction

# Our overlay: debug-on config + a couple of routes + a homepage.
COPY overlay/.env                /app/.env
COPY overlay/web.php             /app/routes/web.php
COPY overlay/welcome.blade.php   /app/resources/views/welcome.blade.php

RUN php artisan key:generate --force \
    && touch /app/database/database.sqlite \
    && chmod -R 777 storage bootstrap/cache \
    && printf 'FLAG{l4r4v3l_1gn1t10n_d3bug_m0d3_rc3_cv3_2021_3129}\n' > /flag.txt

EXPOSE 8000
CMD ["php","artisan","serve","--host=0.0.0.0","--port=8000"]
