from pathlib import Path
import os, http.server, functools, subprocess, threading, signal, time, sys
root=Path(__file__).resolve().parent
class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Cache-Control','no-store')
        super().end_headers()
    def log_message(self,*args):pass
stop=threading.Event()
failure=threading.Event()
for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,lambda *_:stop.set())
server=http.server.HTTPServer(('127.0.0.1',0),functools.partial(Handler,directory=str(root/'site')))
server.timeout=.5
child=subprocess.Popen([str(root/'target/debug/vhalla-webrtc-listener')],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
def output():
    with (root/'native.log').open('w') as log:
        total=0
        for line in iter(lambda: child.stdout.readline(4097), ''):
            total+=len(line)
            if len(line)>4096 or total>262144:
                failure.set();stop.set();break
            log.write(line);log.flush();print(line,end='',flush=True)
thread=threading.Thread(target=output);thread.start()
print(f'SUPERVISOR_PID {os.getpid()}',flush=True)
print(f'URL http://127.0.0.1:{server.server_port}/',flush=True)
try:
    deadline=time.monotonic()+600
    while not stop.is_set() and child.poll() is None and time.monotonic()<deadline:server.handle_request()
finally:
    server.server_close()
    if child.poll() not in (None,0):failure.set()
    if child.poll() is None:child.terminate()
    try:child.wait(timeout=3)
    except subprocess.TimeoutExpired:child.kill();child.wait()
    thread.join(timeout=3)
    if thread.is_alive():failure.set()
sys.exit(1 if failure.is_set() else 0)
