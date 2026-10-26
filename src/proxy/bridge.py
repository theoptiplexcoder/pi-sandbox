import socket, threading, sys

def fwd(s, d):
    try:
        while True:
            b = s.recv(8192)
            if not b:
                break
            d.sendall(b)
    except:
        pass
    finally:
        try:
            s.close()
        except:
            pass
        try:
            d.close()
        except:
            pass

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 3128))
srv.listen(50)

def handle(c):
    try:
        u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        u.connect('/run/pi-sandbox/proxy.sock')
        t1 = threading.Thread(target=fwd, args=(c, u), daemon=True)
        t2 = threading.Thread(target=fwd, args=(u, c), daemon=True)
        t1.start()
        t2.start()
    except Exception as e:
        sys.stderr.write(str(e) + '\n')
        c.close()

while True:
    try:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()
    except:
        break
