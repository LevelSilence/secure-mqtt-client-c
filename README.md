# Secure MQTT Client (C) – Work in Progress

This project is a C re-implementation of the AMQTT Python client.
The goal is to port client-side security logic (RSA key exchange,
XOR-based group key handling, and ASCON encryption) to C while using
Mosquitto as a standard MQTT broker.

## Current Status
- Client data structures implemented
- Configuration and error handling added
- RSA key generation implemented (OpenSSL)
- ASCON encrypt/decrypt helpers implemented
- XOR-based key logic understood and planned

## Not Yet Implemented
- Full MQTT connect logic
- Publish / subscribe flow
- KEYDIS integration with Mosquitto

This repository represents the initial groundwork and will be
incrementally updated.
