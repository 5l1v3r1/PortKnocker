import importlib
import psutil
from subprocess import Popen, CREATE_NEW_CONSOLE
import socket
import threading
import time
import select
from collections import deque
import hashlib


# List of tuples, where the first element in the tuple is the port, and the second is the secret.
ports = [[(34580, "a"), (9047, "b"), (33812, "c"), (45732, "d")],
        [(34580, "w"), (9047, "x"), (33812, "y"), (45732, "z")],
        [(34580, "1"), (9047, "2"), (33812, "3"), (45732, "4")]]


ip_data = {}
request_stop = False
web_server_running = False
reset_timer = False
timeout_lock = threading.Lock()

'''
Pass in the message from the client UDP packet as data, the client's IP, and the secret for whatever port in the sequence this is.
'''
def authenticate_hash(data, ip, secret):
    data = data.decode('utf-8')
    m = hashlib.sha256()
    m.update(ip.encode('utf-8'))
    m.update(secret.encode('utf-8'))
    print("Message from client:                 ", data)
    message = m.hexdigest()
    print("Message generated to match client:   ", message)
    result = message == data
    if result:
        print("Knock accepted for ", ip)
    print("\n")
    return result

'''
This is where all the knock validation occurs. If successful, the webserver is launched, otherwise return with no change of state
'''
def check_knocks(data, addr):
    global ip_data
    # IP of knocker
    ip = addr[0]
    # Port that the IP knocked
    port_knocked = addr[1]

    # Number of knocks already attempted by this client IP (start at 0)
    num_knocks = 0
    # This is the secret associated with this current knock (start at 0)
    secret = ports[0][1]
    total_num_knocks_needed = len(ports)

    # Associate the new knock with the IP
    if ip in ip_data:
        num_knocks = len(ip_data[ip])
        secret = ports[num_knocks][1]
        # If the server hash of the client's IP address and the secret matches the client's data:
        if authenticate_hash(data, ip, secret):
            # After all the checks are complete, finally add the knock to the list of confirmed knocks for comparison later.
            ip_data[ip].append(port_knocked)
            num_knocks = num_knocks + 1
        else:
            print("Authentication failed for knock number: ", num_knocks)
            return
    else:
        if authenticate_hash(data, ip, secret):
            ip_data[ip] = deque([port_knocked])
            # num_knocks guaranteed to be 0 up until this point, so adding 1 is setting it to 1. 
            num_knocks = 1
        else:
            print("Authentication failed")
            return


    # There should be equal or fewer knocks in the knock history (num_knocks) than the number of knocks
    # in the correct sequence (total_num_knocks_needed)
    if num_knocks > total_num_knocks_needed:
        # If this isn't true, then take one knock attempt from the left of the deque (assuming it grows to the right)
        ip_data[ip].popleft()


    # Use list comprehension to get a list of all the ports -- unpacked from their tuples
    port_list = [port[0] for port in ports]
    #print(port_list)

    # If the knock sequence is correct
    if (num_knocks == total_num_knocks_needed) and (list(ip_data[ip]) == port_list):
        print("Knocked correctly")
        ip_data = {}
        open_web_server()

    # Just for the user to see the knocks coming in.
    #print("Current state for ", ip, ":", ip_data)


# Waits 10 seconds and then kills the open webserver
def timeout(pid, start_time):
    global request_stop
    global timeout_lock
    global reset_timer

    while True:
        if reset_timer:
            start_time = time.time()
            reset_timer = False
        curr_time = time.time()
        elapsed = curr_time - start_time
        
        if elapsed >= 10:
            timeout_lock.acquire()
            # Critical section
            try:
                if request_stop is False:
                    print("Timeout thread finishing...")
                    close_web_server(pid)
            finally:
                timeout_lock.release()
            # End critical section            
            return
        time.sleep(0.05)


# This creates a new process and returns the PID. 
# It also creates a timeout thread to close the server in 10 seconds
def open_web_server(): 
    global request_stop
    global reset_timer
    global web_server_running
    request_stop = False

    # If this webserver was already opened and not closed, just refresh the timer instead of reopening it.
    if web_server_running:
        print("Refreshed web server access.")
        reset_timer = True
        return 
    try:
        # proc = Popen('weblite1',creationflags=CREATE_NEW_CONSOLE).pid
        proc = Popen(['weblite1',], shell=False).pid
        start_time = time.time()
        t = threading.Thread(target=timeout, args=(proc, start_time))
        t.start()
        web_server_running = True
    except:
        print("Webserver already binded.")
    print("Opened webserver")
    return proc


# Shut down the webserver by process id. This gets rid of the entire webserver process.
def close_web_server(pid):
    global request_stop
    global web_server_running
    request_stop = True
    try:
        web_server_running = False
        p = psutil.Process(pid)
        p.terminate()
    except:
        print("There isn't a running webserver to be closed.")
        return
    print("Closed webserver")


# Entry point
if __name__ == "__main__":
    # This is the secret sequence

    ip = "127.0.0.1"
    # Populated with sockets that we will be listening for UDP packets on
    sockets = []

    #Create a socket listener for each port
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind((ip, port[0]))
            sockets.append(s)
        except socket.error:
            print('Bind failed.')
        print("UDP Knock listener binded on ", ip, ":", port[0])
       
    # Python's select module fires an event whenever we are ready to process a ready socket (i.e., it will return a list of sockets that are ready to read)
    while True:
        ready, _, _ = select.select(sockets, [], [])
        #print(ready)
        for socket in ready:
            data, _ = socket.recvfrom(1024)
            # If knock sequence completed, then open the server
            if check_knocks(data, socket.getsockname()): # data = a hash from the client, socket.getsockname() = Tuple(IP, Port)
                webserver_pid = open_web_server()
            