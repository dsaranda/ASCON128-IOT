Criptografía Ligera en Dispositivos IoT 🌐🔒


Este proyecto demuestra la implementación del algoritmo criptográfico ASCON-128, diseñado para proporcionar seguridad eficiente en dispositivos IoT con recursos limitados. La solución emplea un microcontrolador Wemos D1 Mini (ESP8266) para encriptar mensajes que son enviados a una Raspberry Pi 3 B mediante el protocolo MQTT.

🚀 Características principales
Dispositivos utilizados:
Wemos D1 Mini: Controla un aro LED NeoPixel y un sensor de movimiento Sharp IR.
Raspberry Pi 3 B: Actúa como servidor MQTT y web, gestionando los mensajes encriptados y desencriptados.
Cifrado ligero: Uso del algoritmo ASCON-128 para asegurar la comunicación.
Protocolo MQTT: Transmisión eficiente de mensajes entre dispositivos IoT.
Visualización web: La Raspberry Pi levanta un servidor Flask que permite interactuar con el sistema, incluyendo botones para encender/apagar los LEDs y ver mensajes encriptados y desencriptados.
⚙️ Funcionalidad
El Wemos D1 Mini:
Encripta mensajes mediante ASCON-128 y los publica en el tema MQTT tu/tema/encryptado.
Publica alertas de movimiento en texto plano en el tema MQTT tu/tema/alertas.
Controla un aro LED NeoPixel y un sensor infrarrojo Sharp IR según comandos recibidos.
La Raspberry Pi 3 B:
Desencripta los mensajes en tu/tema/encryptado y publica el texto plano en el tema textoplano.
Proporciona una interfaz web con botones para encender/apagar el aro LED y visualizar los mensajes encriptados y desencriptados.
🛠️ Requisitos
Hardware:
Wemos D1 Mini
Sensor infrarrojo Sharp IR
Aro LED NeoPixel
Raspberry Pi 3 B
Software:
Biblioteca ASCON en el Wemos D1 Mini.
Servidor Flask en la Raspberry Pi.
Broker MQTT (p. ej., Mosquitto).
📌 Objetivo
Este proyecto busca explorar la viabilidad y eficiencia de la criptografía ligera en escenarios IoT reales, demostrando cómo el algoritmo ASCON-128 puede integrarse para garantizar la seguridad de las comunicaciones.

![image](https://github.com/user-attachments/assets/ba3bf941-bba9-44d1-a46b-e9319b68421c)
