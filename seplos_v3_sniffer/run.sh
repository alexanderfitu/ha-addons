#!/usr/bin/with-contenv bashio
# shellcheck shell=bash
set -e

# MQTT: explicit options win, otherwise take the Mosquitto add-on's service
# details from the Supervisor (no user to create by hand).
if bashio::config.has_value 'mqtt_host'; then
    bashio::log.info "Using MQTT broker from add-on options"
elif bashio::services.available mqtt; then
    export MQTT_HOST="$(bashio::services mqtt 'host')"
    export MQTT_PORT="$(bashio::services mqtt 'port')"
    export MQTT_USER="$(bashio::services mqtt 'username')"
    export MQTT_PASS="$(bashio::services mqtt 'password')"
    bashio::log.info "Using MQTT broker ${MQTT_HOST}:${MQTT_PORT} from the Supervisor"
else
    bashio::log.warning "No MQTT service found; set mqtt_host/mqtt_user/mqtt_password in the options"
fi

export OPTIONS_FILE=/data/options.json
export WEB_PORT=8099

bashio::log.info "Starting Seplos V3 sniffer against $(bashio::config 'waveshare_host'):$(bashio::config 'waveshare_port')"
exec python3 -u /app/seplos_v3_sniffer.py
