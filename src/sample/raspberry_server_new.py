import socket
import numpy as np
import encodings
import Adafruit_DHT


HOST = '10.200.130.36'  # Standard loopback interface address (localhost)
PORT = 1980       # Port to listen on (non-privileged ports are > 1023)

# def random_data():
#     pin = 7
#     sensor = Adafruit_DHT.DHT11
#     humidity, temperature = Adafruit_DHT.read_retry(sensor, pin)
#
#     if humidity is not None and temperature is not None:
#         print('Temp={0:0.1f}*C  Humidity={1:0.1f}%'.format(temperature, humidity))
#         print("data was written on database T{} H{}".format(temperature,humidity))
#         result = '{},{}'.format(temperature,humidity)
#         return result

    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print("Server Started waiting for client to connect ")
            s.bind((HOST, PORT))
            s.listen(5)
            conn, addr = s.accept()

        with conn:
            print('Connected by', addr)

            my_data = "hej"
            x_encoded_data = my_data.encode('utf-8')

            print(x_encoded_data)
            conn.sendall(x_encoded_data)
            conn.close()
            s.close()
