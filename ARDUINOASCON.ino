#include <Adafruit_NeoPixel.h>
#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <SharpIR.h>
#include <ASCON.h>  // Incluir la librería de Ascon128

// Configuración de Wi-Fi
const char* ssid = "WIFI";  // Tu red Wi-Fi
const char* password = "WIFI123"; // Tu contraseña Wi-Fi

// Configuración del broker MQTT
const char* mqtt_server = "IP";  // Dirección IP del broker MQTT
WiFiClient espClient;
PubSubClient client(espClient);

// Configuración del pin del NeoPixel y el sensor IR
#define LED_PIN D5
#define PIN D2  // Pin para el sensor de movimiento
#define NUMPIXELS 24
Adafruit_NeoPixel pixels(NUMPIXELS, LED_PIN, NEO_GRB + NEO_KHZ800);

// Inicializa el objeto SharpIR
SharpIR sensor(SharpIR::GP2Y0A41SK0F, A0);  // Asegúrate de usar el pin adecuado

// Variables para controlar el estado
bool lightOn = false;
bool motionDetected = false;

// Claves y buffers para Ascon128
uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
uint8_t iv[16]; // IV generado aleatoriamente para cada mensaje
uint8_t plaintext[128]; // Buffer para el mensaje original
uint8_t ciphertext[144]; // Buffer para el mensaje encriptado (incluye el tag)
size_t ciphertext_len;

// Función para generar un IV aleatorio
void generate_iv() {
  for (int i = 0; i < 16; i++) {
    iv[i] = random(0, 256);  // Generar un número aleatorio entre 0 y 255
  }
}

// Función para desencriptar y publicar el mensaje en texto plano
void decrypt_and_publish() {
  uint8_t decrypted_text[128]; // Buffer para el mensaje desencriptado
  size_t decrypted_len;

  int result = ascon128_aead_decrypt(decrypted_text, &decrypted_len, ciphertext, ciphertext_len, NULL, 0, iv, key);
  if (result == 0) {
    decrypted_text[decrypted_len] = '\0';  // Asegurar que el texto esté terminado en NULL
    Serial.print("Mensaje desencriptado: ");
    Serial.println((char*)decrypted_text);
    
    // Publicar el mensaje desencriptado en el tópico "textoplano"
    client.publish("tu/texto/plano", (char*)decrypted_text, decrypted_len);
  } else {
    Serial.println("Error en la desencriptación");
  }
}

void setup() {
  Serial.begin(115200);
  setup_wifi();
  client.setServer(mqtt_server, 1883);
  client.setCallback(callback);
  
  pixels.begin();  // Inicializar el NeoPixel
  pixels.clear();
  pixels.show();
  
  pinMode(PIN, INPUT);  // Configurar el pin del sensor IR como entrada
}

// Función para conectar a Wi-Fi
void setup_wifi() {
  delay(10);
  Serial.println("Conectando a Wi-Fi...");
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("Wi-Fi conectado");
}

// Función para reconectar al broker MQTT
void reconnect() {
  while (!client.connected()) {
    Serial.print("Conectando a MQTT...");
    if (client.connect("WemosD1Mini")) {
      Serial.println("Conectado");
      client.subscribe("tu/tema/mqtt");  // Suscribirse al tema para recibir comandos
    } else {
      Serial.print("Error al conectar, reintentando...");
      delay(5000);
    }
  }
}

// Función que se ejecuta cuando se recibe un mensaje MQTT
void callback(char* topic, byte* payload, unsigned int length) {
  String message;
  for (int i = 0; i < length; i++) {
    message += (char)payload[i];
  }

  if (message == "verde") {
    // Activar el aro de luz en verde
    for (int i = 0; i < NUMPIXELS; i++) {
      pixels.setPixelColor(i, pixels.Color(0, 255, 0));  // Color verde
    }
    pixels.show();
    lightOn = true;
    motionDetected = false; // Apagar la detección de movimiento
  } else if (message == "off") {
    // Apagar el aro de luz
    for (int i = 0; i < NUMPIXELS; i++) {
      pixels.setPixelColor(i, pixels.Color(0, 0, 0));  // Apagar
    }
    pixels.show();
    lightOn = false;
    motionDetected = false; // Apagar la detección de movimiento
  }
}

void loop() {
  if (!client.connected()) {
    reconnect();
  }
  client.loop();

  // Detectar movimiento del sensor IR
  int sensorValue = sensor.getDistance();  // Detecta la distancia
  if (sensorValue < 5 && lightOn && !motionDetected) {  // Si hay movimiento y el LED está encendido
    // Cambiar el LED a color rojo
    for (int i = 0; i < NUMPIXELS; i++) {
      pixels.setPixelColor(i, pixels.Color(255, 0, 0));  // Color rojo
    }
    pixels.show();
    
    // Encriptar el mensaje de alerta
    const char* mensaje = "ALERTA SE DETECTO MOVIMIENTO EN LA HABITACION";
    size_t mensaje_len = strlen(mensaje);
    
    // Copiar el mensaje al buffer de texto plano
    memcpy(plaintext, mensaje, mensaje_len);

    // Generar un IV aleatorio
    generate_iv();

    // Encriptar el mensaje
    ascon128_aead_encrypt(ciphertext, &ciphertext_len, plaintext, mensaje_len, NULL, 0, iv, key);

    // Convertir el mensaje encriptado a formato hexadecimal
    char hex_message[ciphertext_len * 2 + 1];  // Buffer para el mensaje en hexadecimal
    for (size_t i = 0; i < ciphertext_len; i++) {
      sprintf(&hex_message[i * 2], "%02X", ciphertext[i]);
    }

    // Publicar el mensaje en texto plano en el tema MQTT "tu/tema/alertas"
    client.publish("tu/tema/alertas", mensaje);
    Serial.println("Mensaje de alerta enviado en texto plano");

    // Publicar el mensaje encriptado en el tema MQTT "tu/tema/encryptado"
    client.publish("tu/tema/encryptado", hex_message);
    Serial.println("Mensaje encriptado enviado en formato hexadecimal");

    // Desencriptar y publicar el mensaje desencriptado
    decrypt_and_publish();

    motionDetected = true; // Evitar que se repita la alerta continuamente
  }

  delay(100);  // Esperar un momento antes de comprobar nuevamente
}