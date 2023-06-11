
# miip.io

## Fork of ifconfig.io
This is a fork of ifconfig.io. Please read the original repo for more configuration instructions.

Original code: https://github.com/georgyo/ifconfig.io/

Original website: https://ifconfig.io/

## My Enhancements
- Maxmind
  - Geo Location
- Plausible Analytics

This repo: https://github.com/xavier-hernandez/miip.io

## Docker-Compose

Here is a sample docker-compose file:

``` bash
version: "3.4"

services:
  miip:
    image: miip.io:latest
    ports:
      - 8080:8080
    environment:
      HOSTNAME: "miip.io"
```
