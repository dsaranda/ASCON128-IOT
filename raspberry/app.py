"""
Servidor del centro de control (Raspberry Pi) · Criptografía ligera ASCON en IoT

Qué hace:
  - Se suscribe por MQTT a las alertas del nodo de campo (Wemos D1 Mini / ESP8266).
  - Verifica el tag y descifra con Ascon-128 cada alerta cifrada.
  - Sirve dos páginas web:
        /             Panel SCADA con el estado del perímetro y el tráfico en vivo
        /paso-a-paso  Explicación del descifrado, fase por fase, con valores reales
  - Envía comandos al nodo (armar/desarmar, cambiar a texto plano o cifrado) y
    permite inyectar un mensaje alterado para demostrar la verificación de integridad.

Formato del mensaje cifrado (tópico tu/tema/encryptado), en hexadecimal:
        nonce (16 bytes) || ciphertext (n bytes) || tag (16 bytes)

AVISO: prueba de concepto de laboratorio. Clave fija, MQTT sin TLS ni autenticación
y panel sin login. Ver la sección "Limitaciones" del README.
"""
from flask import Flask, render_template, jsonify, request
import paho.mqtt.client as mqtt
import threading
import time
from datetime import datetime
from flask_socketio import SocketIO

# Implementación de referencia de los autores de ASCON (pyascon), versión Ascon-128 v1.2.
# Es la misma variante que usa la ascon-suite en el Wemos (rama final-round).
from ascon import ascon_decrypt
import ascon_traza   # Traza didáctica para la página /paso-a-paso

app = Flask(__name__)
socketio = SocketIO(app)   # WebSocket: empuja eventos al navegador en tiempo real

# ---------------------------------------------------------------------------
# Parámetros criptográficos
# ---------------------------------------------------------------------------
# Clave de LABORATORIO: debe coincidir con la del Wemos. No usar en producción.
KEY = bytes(range(16))  # 00 01 02 ... 0F
VARIANTE = "Ascon-128"
NONCE_LEN = 16          # bytes
TAG_LEN = 16            # bytes

# ---------------------------------------------------------------------------
# Configuración MQTT (deben coincidir con los tópicos del .ino)
# ---------------------------------------------------------------------------
mqtt_broker = "127.0.0.1"  # El broker (Mosquitto) corre en la propia Raspberry
mqtt_port = 1883
mqtt_command_topic = "tu/tema/mqtt"          # Salida: comandos hacia el Wemos
mqtt_alert_topic = "tu/tema/alertas"         # Entrada: alertas en texto plano (solo modo "claro")
mqtt_encrypted_topic = "tu/tema/encryptado"  # Entrada: nonce || ciphertext || tag (hex)

# ---------------------------------------------------------------------------
# Estado compartido del panel (en memoria; se reinicia al reiniciar el servicio)
# ---------------------------------------------------------------------------
estado = {
    "armado": False,
    "modo": "cifrado",      # "cifrado" | "claro"
    "verificados": 0,       # alertas con tag válido
    "rechazados": 0,        # alertas con tag inválido o mal formadas
    "en_claro": 0,          # alertas recibidas sin cifrar
    "ultimo": None,         # último evento (para quien abre la página tarde)
}
ultimo_hex = None           # último cifrado válido recibido (base de la demo de manipulación y de la traza)


def nuevo_cliente():
    """Crea un cliente MQTT compatible con paho-mqtt 1.x y 2.x.
    La versión 2.x exige indicar la versión de API de callbacks; la 1.x no la conoce."""
    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)
    except AttributeError:
        return mqtt.Client()


# Cliente aparte para publicar comandos desde las rutas web (el otro queda escuchando en su hilo)
pub_client = nuevo_cliente()


def ahora():
    return datetime.now().strftime("%H:%M:%S")


def emitir_estado():
    """Envía los contadores y el estado actual a todos los navegadores conectados."""
    socketio.emit("estado", {k: v for k, v in estado.items() if k != "ultimo"})


def procesar_cifrado(payload_hex):
    """Verifica el tag y descifra. Devuelve un evento con todo lo que muestra el panel.

    Pasos:
      1. Convierte el texto hexadecimal a bytes (si no es hex válido, se rechaza).
      2. Separa nonce (primeros 16 bytes) y ciphertext+tag (el resto).
      3. ascon_decrypt recalcula el tag y lo compara con el recibido:
         - si coincide, devuelve el texto en claro
         - si no coincide, devuelve None y el texto NUNCA se entrega (propiedad AEAD)
    """
    global ultimo_hex
    ev = {"ts": ahora(), "hex": payload_hex}
    try:
        data = bytes.fromhex(payload_hex.strip())
    except ValueError:
        return {**ev, "tipo": "rechazado", "motivo": "payload no es hexadecimal"}
    if len(data) < NONCE_LEN + TAG_LEN:
        return {**ev, "tipo": "rechazado", "motivo": "payload demasiado corto"}

    nonce, ct = data[:NONCE_LEN], data[NONCE_LEN:]   # ct incluye el tag al final
    ev.update(nonce=nonce.hex().upper(), ct=ct[:-TAG_LEN].hex().upper(), tag=ct[-TAG_LEN:].hex().upper())

    t0 = time.perf_counter()
    pt = ascon_decrypt(KEY, nonce, b"", ct, variant=VARIANTE)   # b"": sin datos asociados
    ev["ms"] = round((time.perf_counter() - t0) * 1000, 2)      # tiempo de descifrado en ms

    if pt is None:
        return {**ev, "tipo": "rechazado", "motivo": "tag inválido: mensaje manipulado o clave incorrecta"}
    ultimo_hex = payload_hex.strip()
    return {**ev, "tipo": "cifrado", "texto": pt.decode(errors="replace")}


def on_connect(client, userdata, flags, rc):
    """Al conectar (o reconectar) al broker, se suscribe a los tópicos de alertas."""
    print("Conectado al broker MQTT, código:", rc)
    client.subscribe(mqtt_alert_topic)
    client.subscribe(mqtt_encrypted_topic)


def on_message(client, userdata, msg):
    """Procesa cada mensaje MQTT entrante, actualiza el estado y lo empuja al navegador."""
    try:
        payload = msg.payload.decode(errors="replace")
        if msg.topic == mqtt_alert_topic:
            # Alerta en texto plano: se muestra tal cual, sin ninguna verificación posible
            ev = {"ts": ahora(), "tipo": "claro", "texto": payload}
            estado["en_claro"] += 1
        elif msg.topic == mqtt_encrypted_topic:
            ev = procesar_cifrado(payload)
            estado["verificados" if ev["tipo"] == "cifrado" else "rechazados"] += 1
        else:
            return
        estado["ultimo"] = ev
        print(f"[{ev['ts']}] {ev['tipo'].upper()}: {ev.get('texto') or ev.get('motivo')}")
        socketio.emit("evento", ev)
        emitir_estado()
    except Exception as e:
        # Un mensaje malformado no debe tirar abajo el servidor
        print(f"Error procesando mensaje de {msg.topic}: {e}")


def start_mqtt():
    """Bucle de escucha MQTT (corre en un hilo aparte para no bloquear el servidor web)."""
    client = nuevo_cliente()
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(mqtt_broker, mqtt_port, 60)
    client.loop_forever()   # Incluye reconexión automática si el broker se reinicia


def publicar(topic, payload):
    """Publica un mensaje puntual (comandos al Wemos o la demo de manipulación)."""
    pub_client.connect(mqtt_broker, mqtt_port, 60)
    pub_client.publish(topic, payload)
    pub_client.disconnect()


mqtt_thread = threading.Thread(target=start_mqtt, daemon=True)
mqtt_thread.start()


# ---------------------------------------------------------------------------
# Rutas web
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    """Panel SCADA."""
    return render_template('index.html')


@app.route('/paso-a-paso')
def paso_a_paso():
    """Presentación del descifrado paso a paso (para proyector)."""
    return render_template('paso.html')


@app.route('/hmi')
def hmi():
    """Pantalla HMI ficticia para la pantalla táctil de 5" (800x480) en modo kiosco."""
    return render_template('hmi.html')


@app.route('/api/traza')
def api_traza():
    """Traza didáctica del descifrado.
    fuente=ultimo : usa el último mensaje real del Wemos (si no hay, genera uno de demostración)
    alterar=1     : altera un bit del cifrado para mostrar el rechazo por tag inválido"""
    fuente = request.args.get("fuente", "ultimo")
    hx = ultimo_hex if (fuente == "ultimo" and ultimo_hex) else None
    origen = "wemos" if hx else "demo"
    if not hx:
        hx = ascon_traza.mensaje_demo(KEY)
    if request.args.get("alterar") == "1":
        pos = NONCE_LEN * 2 + 4  # mismo nibble que la demo de manipulación
        hx = hx[:pos] + format(int(hx[pos], 16) ^ 0x1, "X") + hx[pos + 1:]
    try:
        t = ascon_traza.trazar(hx, KEY)
    except Exception as e:
        return jsonify(error=str(e)), 400
    t["origen"] = origen
    t["ts"] = (estado["ultimo"] or {}).get("ts") if origen == "wemos" else ahora()
    return jsonify(t)


@app.route('/estado')
def get_estado():
    """Estado actual (lo usa el panel al abrirse para mostrar el último evento)."""
    return jsonify(estado)


@app.route('/turn_on_led', methods=['POST'])
def turn_on_led():
    """Arma el perímetro: el Wemos pone el aro en verde y empieza a vigilar."""
    estado["armado"] = True
    publicar(mqtt_command_topic, "verde")
    emitir_estado()
    return jsonify(status="ok")


@app.route('/turn_off_led', methods=['POST'])
def turn_off_led():
    """Desarma el perímetro y limpia el último evento."""
    estado["armado"] = False
    estado["ultimo"] = None
    publicar(mqtt_command_topic, "off")
    emitir_estado()
    return jsonify(status="ok")


@app.route('/modo/<modo>', methods=['POST'])
def cambiar_modo(modo):
    """Cambia cómo envía las alertas el Wemos: 'cifrado' (ASCON) o 'claro' (demo del antes)."""
    if modo not in ("cifrado", "claro"):
        return jsonify(status="error", motivo="modo inválido"), 400
    estado["modo"] = modo
    publicar(mqtt_command_topic, modo)
    emitir_estado()
    return jsonify(status="ok")


@app.route('/manipular', methods=['POST'])
def manipular():
    """Demo de integridad: reinyecta el último cifrado con un bit alterado, como haría un atacante en la red.
    El servidor lo recibe como cualquier otro mensaje y debe rechazarlo por tag inválido."""
    if not ultimo_hex:
        return jsonify(status="error", motivo="todavía no hay un mensaje cifrado para alterar"), 409
    pos = NONCE_LEN * 2 + 4  # un nibble dentro del ciphertext (después de los 32 dígitos del nonce)
    alterado = ultimo_hex[:pos] + format(int(ultimo_hex[pos], 16) ^ 0x1, "X") + ultimo_hex[pos + 1:]
    publicar(mqtt_encrypted_topic, alterado)
    return jsonify(status="ok")


if __name__ == '__main__':
    # debug=False: el debugger de Werkzeug permite ejecución remota de código si queda expuesto en la red.
    # host="0.0.0.0": escucha en todas las interfaces (punto de acceso y red local).
    try:
        socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
    except TypeError:  # versiones viejas de Flask-SocketIO no tienen ese parámetro
        socketio.run(app, host="0.0.0.0", port=5000, debug=False)
