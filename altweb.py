import http.server, socketserver, urllib.parse, json, http.client, time, threading, requests, os, logging, sys
from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from win10toast import ToastNotifier
import tkinter as tk
from pystray import MenuItem, Icon
from PIL import Image, ImageDraw

def taskbar():
    root = tk.Tk()
    root.title("AltWeb")
    root.withdraw()
    icon = Icon("AltWeb")
    icon.icon = Image.new("RGB", (16, 16), "grey")
    icon.menu = (MenuItem("Exit", lambda: [icon.stop(), root.destroy(), os._exit(0)]),)
    icon.run()
    root.mainloop()

app = Flask(__name__)
limiter = Limiter(app,default_limits=["6 per minute"])

def notification(subject, message):
    try:
        ToastNotifier().show_toast(subject, message, duration=5)
    except:
        pass
@app.route('/send', methods=['GET'])
@limiter.limit("6 per minute")
def receive_notification():
    if request.args.get('subject') and request.args.get('message'):
        threading.Thread(target=notification, args=(request.args.get('subject'), request.args.get('message'))).start()
        return '+'
    else:
        return '-'

if not os.path.isfile(os.path.expanduser('~/.awc-conf')):
    with open(os.path.expanduser('~/.awc-conf'), 'a') as f:
        f.write("""BLOCKED_DOMAINS = altweb.stinks, altweb-is-bad.site
BLOCKED_HTTP_METHODS = []
ALTWEB_PROXY_PORT = 8080
ALTWEB_NOTIFICATION_API_PORT = 21000
BLOCK_FILENAMES = []
NETWORK_LOGGING = No
""")

conf = {k.strip(): v.strip() for k, v in (line.split('=') for line in open(os.path.expanduser('~/.awc-conf')))}

domains = {}
ALTWEB_PROXY_PORT = int(conf.get('ALTWEB_PROXY_PORT', 8080))
ALTWEB_NOTIFICATION_API_PORT = int(conf.get('ALTWEB_NOTIFICATION_API_PORT', 21000))

def network_log(url, method, headers, data, body):
    logs = open("network.log", "a")
    logs.write("URL: " + url + "\n")
    logs.write("Method: " + method + "\n")
    if headers:
        logs.write("Headers: " + headers + "\n")
    if data:
        logs.write("Data: " + data + "\n")
    logs.write("Body: " + body + "\n")
    logs.write("__________________________________________________________\n")

BLOCKED_DOMAINS = {domain.strip(): True for domain in conf.get('BLOCKED_DOMAINS', "").split(",")}
BLOCKED_HTTP_METHODS = set(json.loads(conf.get('BLOCKED_HTTP_METHODS', "[]")))
BLOCK_FILENAMES = set(json.loads(conf.get('BLOCK_FILENAMES', "[]")))
NETWORK_LOGGING = set(conf.get('NETWORK_LOGGING', "No"))

class Net(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def blockfile(self, path):
        filename = os.path.basename(urllib.parse.urlparse(path).path)
        return filename in BLOCK_FILENAMES

    def do_GET(self):
        domain = urllib.parse.urlparse(self.path).netloc.split(":")[0]
        url = urllib.parse.urlparse(self.path)

        if domain in BLOCKED_DOMAINS:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Domain is blocked by AltWeb Configuration")
            return

        if self.blockfile(url.path):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"File is blocked by AltWeb Configuration")
            return
        
        if domain not in domains:
            try:
                response = requests.get(f"http://domains.sevenworks.eu.org/lookup?domain={domain}", headers={"User-Agent": "altweb-domain-fetch"})
                content = json.loads(response.text)
                if domain in content:
                    domains[domain] = content[domain]
                else:
                    return
            except:
                return

        self.fetch("GET", domains[domain], url)

    def do_POST(self):
        domain = urllib.parse.urlparse(self.path).netloc.split(":")[0]
        url = urllib.parse.urlparse(self.path)
        if domain in domains:
            if domain in BLOCKED_DOMAINS:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Domain is blocked by AltWeb Configuration")
                return
            if self.blockfile(url.path):
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"File is blocked by AltWeb Configuration")
                return
            else:
                self.fetch("POST", domains[domain], url)
                return
        else:
            pass

    def do_PUT(self):
        domain = urllib.parse.urlparse(self.path).netloc.split(":")[0]
        url = urllib.parse.urlparse(self.path)
        if domain in domains:
            if domain in BLOCKED_DOMAINS:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Domain is blocked by AltWeb Configuration")
                return
            if self.blockfile(url.path):
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"File is blocked by AltWeb Configuration")
                return
            else:
                self.fetch("PUT", domains[domain], url)
                return
        else:
            pass

    def do_DELETE(self):
        domain = urllib.parse.urlparse(self.path).netloc.split(":")[0]
        url = urllib.parse.urlparse(self.path)
        if domain in domains:
            if domain in BLOCKED_DOMAINS:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Domain is blocked by AltWeb Configuration")
                return
            if self.blockfile(url.path):
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"File is blocked by AltWeb Configuration")
                return
            else:
                self.fetch("DELETE", domains[domain], url)
                return
        else:
            pass

    def do_PATCH(self):
        domain = urllib.parse.urlparse(self.path).netloc.split(":")[0]
        url = urllib.parse.urlparse(self.path)
        if domain in domains:
            if domain in BLOCKED_DOMAINS:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Domain is blocked by AltWeb Configuration")
                return
            if self.blockfile(url.path):
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"File is blocked by AltWeb Configuration")
                return
            else:
                self.fetch("PATCH", domains[domain], url)
                return
        else:
            pass

    def do_HEAD(self):
        domain = urllib.parse.urlparse(self.path).netloc.split(":")[0]
        url = urllib.parse.urlparse(self.path)
        if domain in domains:
            if domain in BLOCKED_DOMAINS:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Domain is blocked by AltWeb Configuration")
                return
            if self.blockfile(url.path):
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"File is blocked by AltWeb Configuration")
                return
            else:
                self.fetch("HEAD", domains[domain], url)
                return
        else:
            pass

    def do_CONNECT(self):
        domain = urllib.parse.urlparse(self.path).netloc.split(":")[0]
        url = urllib.parse.urlparse(self.path)
        if domain in domains:
            if domain in BLOCKED_DOMAINS:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Domain is blocked by AltWeb Configuration")
                return
            if self.blockfile(url.path):
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"File is blocked by AltWeb Configuration")
                return
            else:
                self.fetch("CONNECT", domains[domain], url)
                return
        else:
            pass
   
    def fetch(self, method, hostname, url):
        conn = http.client.HTTPConnection(hostname)
        conn.request(method, url.path + ('?' + url.query if url.query else ''))
        response = conn.getresponse()
        content_type = response.getheader('Content-Type', '')
        if content_type.startswith('text'):
            body = response.read().decode('utf-8')
            if NETWORK_LOGGING == "Yes": network_log(url.geturl(), method, str(response.getheaders()), "", body)
            self.send_response(response.status)
            for header, value in response.getheaders():
                self.send_header(header, value)
            self.end_headers()
            self.wfile.write(body.encode('utf-8'))
        else:
            self.send_response(response.status)
            for header, value in response.getheaders():
                self.send_header(header, value)
            self.end_headers()
            self.wfile.write(response.read())

def main():
    with socketserver.ThreadingTCPServer(("", ALTWEB_PROXY_PORT), Net) as httpd:
        threading.Thread(target=taskbar).start()
        print(f"AltWeb is Running: 127.0.0.1:{ALTWEB_PROXY_PORT}")
        threading.Thread(target=httpd.serve_forever).start()
        logging.getLogger('werkzeug').disabled = True
        sys.modules['flask.cli'].show_server_banner = lambda *x: print(f"AltWeb Notification API is Running: 127.0.0.1:{ALTWEB_NOTIFICATION_API_PORT}/send?subject=&message=")
        app.run(port=ALTWEB_NOTIFICATION_API_PORT)

if __name__ == "__main__":
    main()