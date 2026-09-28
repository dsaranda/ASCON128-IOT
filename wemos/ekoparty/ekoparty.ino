/*
 * ============================================================================
 *  Nodo de campo N-01 · Criptografía ligera ASCON en IoT
 * ============================================================================
 *  Hardware: Wemos D1 Mini (ESP8266) + sensor Sharp IR GP2Y0A41SK0F + aro NeoPixel (24 LEDs)
 *
 *  Funcionamiento:
 *   1. La Raspberry Pi "arma" el perímetro por MQTT (comando "verde") -> aro verde.
 *   2. Si el sensor detecta algo a menos de ~5 cm -> aro rojo y se envía una alerta.
 *   3. La alerta se cifra con Ascon-128 (AEAD) y se publica como:
 *          nonce (16 B) || ciphertext || tag (16 B)   codificado en hexadecimal
 *   4. La Raspberry Pi verifica el tag y descifra en Python (ver raspberry/app.py).
 *
 *  Modo "claro" (demo del antes/después): la alerta se publica en texto plano,
 *  para mostrar qué ve un atacante en la red cuando no hay cifrado.
 *
 *  Librería ASCON: ascon-suite de Rhys Weatherley, rama "final-round"
 *  (Ascon-128 v1.2, versión ganadora del concurso NIST LWC). Se fija esa rama
 *  porque el estándar final (NIST SP 800-232, Ascon-AEAD128) no es compatible
 *  byte a byte y rompería el descifrado en Python.
 *
 *  AVISO: prueba de concepto de laboratorio. La clave es fija y MQTT no usa TLS
 *  ni autenticación. No usar esta configuración en producción.
 * ============================================================================
 */

#include <Adafruit_NeoPixel.h>   // Control del aro de LEDs
#include <ESP8266WiFi.h>         // Conexión WiFi del ESP8266
#include <PubSubClient.h>        // Cliente MQTT
#include <SharpIR.h>             // Sensor de distancia infrarrojo (Giuseppe Masino)
#include <ASCON.h>               // ascon-suite (rweather), rama final-round = Ascon-128 v1.2

// ---------------------------------------------------------------------------
// Red y broker
// ---------------------------------------------------------------------------
// Red WiFi que crea la Raspberry Pi (punto de acceso con el adaptador USB).
// Completar con los valores propios antes de compilar. No subir credenciales reales al repositorio.
const char* ssid = "TU_RED";
const char* password = "TU_CLAVE";

// La Raspberry Pi tiene IP fija en su punto de acceso y ahí corre el broker Mosquitto.
const char* mqtt_server = "192.168.50.1";
WiFiClient espClient;             // Conexión TCP que usa el cliente MQTT
PubSubClient client(espClient);   // Cliente MQTT sobre esa conexión

// Tópicos MQTT (deben coincidir con los de raspberry/app.py)
#define TOPIC_COMANDOS  "tu/tema/mqtt"        // Entrada: comandos de la Raspberry (verde / off / claro / cifrado)
#define TOPIC_CIFRADO   "tu/tema/encryptado"  // Salida: nonce || ciphertext || tag en hexadecimal
#define TOPIC_CLARO     "tu/tema/alertas"     // Salida: alerta en texto plano (solo en modo "claro")

// ---------------------------------------------------------------------------
// Hardware
// ---------------------------------------------------------------------------
#define LED_PIN D5     // Línea de datos (DIN) del aro NeoPixel
#define PIN D2         // Reservado (el sensor Sharp IR es analógico y se lee por A0)
#define NUMPIXELS 24   // Cantidad de LEDs del aro
Adafruit_NeoPixel pixels(NUMPIXELS, LED_PIN, NEO_GRB + NEO_KHZ800);

// Sensor Sharp IR modelo GP2Y0A41SK0F (rango 4-30 cm) conectado a la entrada analógica A0
SharpIR sensor(SharpIR::GP2Y0A41SK0F, A0);

// ---------------------------------------------------------------------------
// Estado del nodo
// ---------------------------------------------------------------------------
bool lightOn = false;        // true = perímetro armado (aro verde, sensor vigilando)
bool motionDetected = false; // true = ya se envió la alerta; evita repetirla hasta rearmar
bool modoCifrado = true;     // true = publica solo cifrado | false = publica en texto plano (demo "antes")

// ---------------------------------------------------------------------------
// Material criptográfico
// ---------------------------------------------------------------------------
// Clave simétrica de 128 bits compartida con la Raspberry Pi (misma que KEY en app.py).
// Clave de LABORATORIO (00 01 02 ... 0F): es pública a propósito para la demo.
uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
uint8_t nonce[16];        // Nonce de 128 bits: único por mensaje, no secreto, viaja junto al cifrado
uint8_t plaintext[128];   // Buffer del mensaje en claro
uint8_t ciphertext[144];  // Buffer del cifrado: mismo largo que el mensaje + 16 bytes de tag
size_t ciphertext_len;    // Largo real del cifrado (lo completa la función de cifrado)

// Genera un nonce nuevo usando el generador de números aleatorios por hardware del ESP8266.
// RANDOM_REG32 devuelve 32 bits aleatorios por lectura; se leen 4 veces para completar 16 bytes.
// En Ascon, repetir un nonce con la misma clave rompe la confidencialidad: por eso se regenera en cada alerta.
void generate_nonce() {
  for (int i = 0; i < 16; i += 4) {
    uint32_t r = RANDOM_REG32;
    memcpy(&nonce[i], &r, 4);
  }
}

// Pinta los 24 LEDs del aro con un mismo color (r, g, b de 0 a 255).
void setColor(uint8_t r, uint8_t g, uint8_t b) {
  for (int i = 0; i < NUMPIXELS; i++) {
    pixels.setPixelColor(i, pixels.Color(r, g, b));
  }
  pixels.show();  // Envía los colores al aro
}

void setup() {
  Serial.begin(115200);  // Monitor Serie para diagnóstico
  setup_wifi();

  client.setServer(mqtt_server, 1883);
  // El payload hexadecimal (nonce + cifrado + tag = 154 caracteres) más los encabezados MQTT
  // puede superar el buffer por defecto de PubSubClient (256 bytes). Se amplía para no perder mensajes.
  client.setBufferSize(512);
  client.setCallback(callback);  // Función que procesa los comandos recibidos

  pixels.begin();   // Inicializa el aro
  pixels.clear();   // Todos los LEDs apagados
  pixels.show();

  pinMode(PIN, INPUT);
}

// Conecta a la red WiFi y espera hasta lograrlo.
// Si la Raspberry todavía no levantó el punto de acceso, sigue intentando.
// Una vez conectado, el ESP8266 se reconecta solo si la red se cae.
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

// (Re)conecta al broker MQTT y se suscribe al tópico de comandos.
// Se llama desde loop() cada vez que la conexión se pierde.
void reconnect() {
  while (!client.connected()) {
    Serial.print("Conectando a MQTT...");
    if (client.connect("WemosD1Mini")) {   // Identificador de cliente MQTT
      Serial.println("Conectado");
      client.subscribe(TOPIC_COMANDOS);
    } else {
      Serial.print("Error al conectar, reintentando...");
      delay(5000);
    }
  }
}

// Se ejecuta cada vez que llega un mensaje al tópico de comandos.
//   "verde"   -> arma el perímetro (aro verde, sensor activo)
//   "off"     -> desarma (aro apagado)
//   "claro"   -> las próximas alertas salen en texto plano (demo del "antes")
//   "cifrado" -> las próximas alertas salen cifradas con ASCON (modo normal)
// Nota de seguridad: los comandos no están autenticados; cualquiera en la red podría enviarlos.
void callback(char* topic, byte* payload, unsigned int length) {
  // El payload MQTT no termina en '\0': se copia a un String carácter por carácter
  String message;
  for (unsigned int i = 0; i < length; i++) {
    message += (char)payload[i];
  }

  if (message == "verde") {
    setColor(0, 255, 0);
    lightOn = true;
    motionDetected = false;   // Permite una nueva alerta
  } else if (message == "off") {
    setColor(0, 0, 0);
    lightOn = false;
    motionDetected = false;
  } else if (message == "claro") {
    modoCifrado = false;
    Serial.println("Modo: TEXTO PLANO");
  } else if (message == "cifrado") {
    modoCifrado = true;
    Serial.println("Modo: CIFRADO ASCON");
  }
}

// Construye y publica la alerta, cifrada o en claro según el modo actual.
void enviar_alerta() {
  const char* mensaje = "ALERTA SE DETECTO MOVIMIENTO EN LA HABITACION";
  size_t mensaje_len = strlen(mensaje);   // 45 bytes

  // Modo "antes": el mensaje viaja en claro y cualquiera conectado a la red puede leerlo o falsificarlo
  if (!modoCifrado) {
    client.publish(TOPIC_CLARO, mensaje);
    Serial.println("Alerta enviada en TEXTO PLANO");
    return;
  }

  // Modo "después": solo sale de la placa el mensaje cifrado y autenticado
  memcpy(plaintext, mensaje, mensaje_len);
  generate_nonce();   // Nonce nuevo para este mensaje

  // Cifrado autenticado Ascon-128:
  //   entrada: mensaje, datos asociados (ninguno: NULL, 0), nonce y clave
  //   salida : ciphertext (45 bytes) seguido del tag de autenticación (16 bytes)
  // Se mide el tiempo en microsegundos para mostrar el costo real en el microcontrolador.
  unsigned long t0 = micros();
  ascon128_aead_encrypt(ciphertext, &ciphertext_len, plaintext, mensaje_len, NULL, 0, nonce, key);
  unsigned long t1 = micros();

  // Arma el payload: nonce (16) || ciphertext || tag (16), cada byte como 2 dígitos hexadecimales.
  // El nonce viaja en claro porque el receptor lo necesita para descifrar; no es secreto.
  size_t total = 16 + ciphertext_len;
  char hex_message[total * 2 + 1];   // +1 para el terminador '\0'
  for (size_t i = 0; i < 16; i++) {
    sprintf(&hex_message[i * 2], "%02X", nonce[i]);
  }
  for (size_t i = 0; i < ciphertext_len; i++) {
    sprintf(&hex_message[(16 + i) * 2], "%02X", ciphertext[i]);
  }
  hex_message[total * 2] = '\0';

  client.publish(TOPIC_CIFRADO, hex_message);
  Serial.print("Alerta CIFRADA enviada. Tiempo de cifrado (us): ");
  Serial.println(t1 - t0);
}

void loop() {
  // Mantiene viva la conexión MQTT y procesa los comandos entrantes
  if (!client.connected()) {
    reconnect();
  }
  client.loop();

  // Lee la distancia en cm. La librería devuelve 3 cuando el objeto está demasiado cerca.
  int sensorValue = sensor.getDistance();

  // Dispara una sola alerta por armado: objeto a menos de 5 cm, perímetro armado y sin alerta previa
  if (sensorValue < 5 && lightOn && !motionDetected) {
    setColor(255, 0, 0);     // Aro rojo: intrusión
    enviar_alerta();
    motionDetected = true;   // No repetir hasta que se vuelva a armar
  }

  delay(100);  // Lectura cada ~100 ms
}
