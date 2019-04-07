import socket 
import sys
import time
import hashlib

'''
Send a UDP datagram containing a hashed message to ip:port 
'''


'''
Configure ports, secrets, and IP
'''
ip = "127.0.0.1"
ports = [(34580, "a"), (9047, "b"), (33812, "c"), (45732, "d")]


def send(ip, port, message):
    clientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSock.sendto(message, (ip, port))

def knock(port):
    # Each port is a tuple, so get the second element of the tuple as the secret.
    secret = port[1]

    # Hash the IP and the secret
    m = hashlib.sha256()
    m.update(ip.encode('utf-8'))
    m.update(secret.encode('utf-8'))
    message = m.hexdigest()

    
    print("Sent ", message, " to ", ip, ":", port[0])

    send(ip, port[0], message.encode('utf-8'))

if __name__ == "__main__":
    for port in ports:
        time.sleep(0.10)
        knock(port)



   