from flask import Flask, render_template, jsonify, request
import paho.mqtt.client as mqtt
import threading
from flask_socketio import SocketIO, emit

# Creamos una instancia de la aplicación Flask
app = Flask(__name__)
socketio = SocketIO(app)

# Variables globales para almacenar el estado de la luz, el mensaje de alerta, y los mensajes de los tópicos
alert_message = None  # Mensaje de alerta recibido a través de MQTT
light_status = "off"  # Estado de la luz (encendida o apagada)
encrypted_message = None  # Mensaje encriptado recibido a través de MQTT
decrypted_message = None  # Mensaje desencriptado

# Configuración del broker MQTT
mqtt_broker = "IP"  # Dirección IP del broker MQTT
mqtt_port = 1883  # Puerto del broker MQTT (por defecto para MQTT)
mqtt_alert_topic = "tu/tema/alertas"  # Tema MQTT para recibir alertas en texto plano
mqtt_encrypted_topic = "tu/tema/encryptado"  # Tema MQTT para recibir mensajes encriptados
mqtt_decrypted_topic = "tu/texto/plano"  # Tema MQTT para recibir el mensaje desencriptado

# Función que maneja la conexión al broker MQTT
def on_connect(client, userdata, flags, rc):
    print("Conectado al broker MQTT con código de resultado: " + str(rc))  # Imprime el código de conexión
    client.subscribe(mqtt_alert_topic)  # Se suscribe al tema de alertas
    client.subscribe(mqtt_encrypted_topic)  # Se suscribe al tema de mensajes encriptados
    client.subscribe(mqtt_decrypted_topic)  # Se suscribe al tema de mensajes desencriptados

# Función que maneja los mensajes recibidos del broker MQTT
def on_message(client, userdata, msg):
    global alert_message, encrypted_message, decrypted_message
    try:
        if msg.topic == mqtt_alert_topic:  # Si el mensaje es del tema de alertas
            alert_message = msg.payload.decode()  # Intenta decodificar el mensaje de alerta en texto plano
            print("Mensaje de alerta recibido:", alert_message)  # Imprime el mensaje recibido
            socketio.emit('alert', {'message': alert_message})  # Envía el mensaje de alerta a todos los clientes

        elif msg.topic == mqtt_encrypted_topic:  # Si el mensaje es del tema de mensajes encriptados
            encrypted_message = msg.payload.decode()  # Intenta decodificar el mensaje encriptado
            print("Mensaje encriptado recibido:", encrypted_message)  # Imprime el mensaje recibido
            socketio.emit('encrypted_message', {'message': encrypted_message})  # Envía el mensaje encriptado a todos los clientes

        elif msg.topic == mqtt_decrypted_topic:  # Si el mensaje es del tema de texto plano desencriptado
            decrypted_message = msg.payload.decode()  # Intenta decodificar el mensaje desencriptado
            print("Mensaje desencriptado recibido:", decrypted_message)  # Imprime el mensaje recibido
            socketio.emit('decrypted_message', {'message': decrypted_message})  # Envía el mensaje desencriptado a todos los clientes

    except UnicodeDecodeError as e:
        print(f"Error al decodificar el mensaje del tema {msg.topic}: {e}")
        # Aquí puedes agregar lógica para manejar el error, como registrar el error o notificar al usuario

    except Exception as e:
        print(f"Error general en el manejo del mensaje MQTT: {e}")

# Función para iniciar el cliente MQTT en un hilo separado
def start_mqtt():
    client = mqtt.Client()  # Crea una instancia del cliente MQTT
    client.on_connect = on_connect  # Asocia la función de conexión
    client.on_message = on_message  # Asocia la función que maneja los mensajes
    client.connect(mqtt_broker, mqtt_port, 60)  # Conecta al broker MQTT
    client.loop_forever()  # Inicia el bucle que mantiene la conexión MQTT activa

# Iniciamos el cliente MQTT en un hilo separado para no bloquear el hilo principal
mqtt_thread = threading.Thread(target=start_mqtt)  # Crea un hilo para ejecutar la función de MQTT
mqtt_thread.daemon = True  # Marca el hilo como "daemon", lo que significa que se cierra cuando la aplicación principal se cierre
mqtt_thread.start()  # Inicia el hilo de MQTT

# Ruta principal que renderiza la página web
@app.route('/')
def index():
    return render_template('index.html', light_status=light_status, alert_message=alert_message,
                           encrypted_message=encrypted_message, decrypted_message=decrypted_message)

# Ruta para encender el LED y publicar un mensaje MQTT
@app.route('/turn_on_led', methods=['POST'])
def turn_on_led():
    global light_status
    light_status = "on"  # Cambia el estado de la luz a "on"
    mqtt_client = mqtt.Client()  # Crea un nuevo cliente MQTT
    mqtt_client.connect(mqtt_broker, mqtt_port, 60)  # Conecta al broker MQTT
    mqtt_client.publish("tu/tema/mqtt", "verde")  # Publica el mensaje "verde" en el tema correspondiente
    return jsonify(status="ok")  # Devuelve una respuesta JSON indicando que la operación fue exitosa

# Ruta para apagar el LED y publicar un mensaje MQTT
@app.route('/turn_off_led', methods=['POST'])
def turn_off_led():
    global light_status, alert_message, encrypted_message, decrypted_message
    light_status = "off"  # Cambia el estado de la luz a "off"
    alert_message = None  # Resetea el mensaje de alerta
    encrypted_message = None  # Resetea el mensaje encriptado
    decrypted_message = None  # Resetea el mensaje desencriptado
    mqtt_client = mqtt.Client()  # Crea un nuevo cliente MQTT
    mqtt_client.connect(mqtt_broker, mqtt_port, 60)  # Conecta al broker MQTT
    mqtt_client.publish("tu/tema/mqtt", "off")  # Publica el mensaje "off" en el tema correspondiente
    return jsonify(status="ok")  # Devuelve una respuesta JSON indicando que la operación fue exitosa

# Ruta para obtener el mensaje de alerta actual
@app.route('/get_alert')
def get_alert():
    return jsonify(alert_message=alert_message)  # Devuelve el mensaje de alerta actual en formato JSON

# Arrancamos la aplicación Flask en el puerto 5000 y aceptando conexiones desde cualquier dirección IP
if __name__ == '__main__':
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
