# Secure Smart-Home Communication using MQTT

A secure smart-home communication system using MQTT, ESP32, Raspberry Pi, ML-KEM-512, and AES-256-GCM.

## 📌 Project Overview

This project demonstrates a secure IoT communication system for a smart-home environment. The system uses an ESP32 device to detect button actions and communicate with an MQTT broker running on a Raspberry Pi.

The project focuses on secure and reliable communication between IoT devices using MQTT and cryptographic techniques.

The system includes:

- ESP32 for IoT device control
- Raspberry Pi as the MQTT broker
- MQTT for message communication
- Push button for user input
- LEDs for device status indication
- ML-KEM-512 for post-quantum key exchange
- AES-256-GCM for secure data encryption

## 🎯 Objectives

- Implement MQTT-based communication between IoT devices.
- Establish communication between an ESP32 and Raspberry Pi.
- Test smart-home message transmission using MQTT.
- Explore post-quantum cryptography using ML-KEM-512.
- Protect communication using AES-256-GCM encryption.
- Demonstrate the system using a physical hardware setup.

## 🛠️ Technologies Used

- ESP32
- Raspberry Pi
- MQTT
- Mosquitto MQTT Broker
- Arduino IDE
- C/C++
- ML-KEM-512
- AES-256-GCM
- Raspberry Pi OS

## 🔧 Hardware Components

The implemented prototype includes:

- ESP32 development board
- Raspberry Pi
- Push button
- LEDs
- Resistors
- Breadboard
- Jumper wires
- USB cables

## 📡 System Architecture

The communication flow is based on MQTT:

```text
              MQTT Communication
                   
        ┌─────────────────┐
        │      ESP32      │
        │  Button / LEDs  │
        └────────┬────────┘
                 │
                 │ MQTT
                 ▼
        ┌─────────────────┐
        │  Raspberry Pi   │
        │  MQTT Broker    │
        │   Mosquitto     │
        └────────┬────────┘
                 │
                 │ MQTT
                 ▼
        ┌─────────────────┐
        │    Subscriber   │
        │ Smart-Home App  │
        └─────────────────┘
