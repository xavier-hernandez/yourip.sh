
# yourip.sh

## Fork of ifconfig.io
This is a fork of ifconfig.io. Please read the original repo for more configuration instructions.

Original code: https://github.com/georgyo/ifconfig.io/

Original website: https://ifconfig.io/

## My Enhancements
- Maxmind
  - Geo Location API or Local databases
- Plausible Analytics

This repo: https://github.com/xavier-hernandez/ipreveal.cc

Docker Image: https://hub.docker.com/r/xavierh/ipreveal

Website: https://yourip.sh

## Docker-Compose

Here is a sample docker-compose file:

``` bash
version: "3.4"

services:
  ipreveal:

    container_name: ipreveal
    image: xavierh/ipreveal:latest
    ports:
      - 8080:8080
    environment:
      HOSTNAME: "ipreveal.cc"
      MAXMIND_USERNAME: [USERNAME] #internal GeoLite2 databases are used if your not passing a username or password 
      MAXMIND_PASSWORD: [PASSWORD] #internal GeoLite2 databases are used if your not passing a username or password
      PLAUSIBLE: [PLAUSIBLE_DOMAIN] #entering a domain here will enable the snippet
      PLAUSIBLE_SELF_HOSTED_DOMAIN: [PLAUSIBLE_SELF_HOSTED_DOMAIN] #meant to set the JS script to your self hosted domain
      FORWARD_IP_HEADER: X-Forwarded-For #if using npm as proxy
      ICON_HTML: #OPTIONAL - Place any HTML here that you'd like to show in the top right of the page
```
# **Disclaimer**
This product includes GeoLite2 data created by MaxMind, available from
<a href="https://www.maxmind.com">https://www.maxmind.com</a>.






