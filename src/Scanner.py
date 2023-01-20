import argparse
import nmap
import requests
import logging
from flask import Flask, render_template, request
import csv

logging.basicConfig(filename='scanner.log', level=logging.DEBUG)
app = Flask(__name__)

parser = argparse.ArgumentParser(description="Network Scanner")
parser.add_argument("-i", "--ip", dest="ip_range", help="IP range to scan")
parser.add_argument("-p", "--port", dest="port_range", help="Port range to scan")
parser.add_argument("-t", "--timeout", dest="timeout", help="Timeout for the connection", default=1)
args = parser.parse_args()

def check_vulnerabilities(host,port):
    url="https://vuln-db.com/api/vulnerabilities?host={}&port={}".format(host,port)
    response = requests.get(url)
    vulnerabilities = response.json()
    if vulnerabilities:
        print("vulnerabilities found:")
        for vulnerability in vulnerabilities:
            print("-{}:{}".format(vulnerability['name'],vulnerability['description']))
    else:
            print("No Vulnerabilities found.")
def save_results(results, file_name):
    with open(file_name, mode='w', newline="") as file:
        writer =csv.writer(file)
        writer.writerow(['Host', 'Port', 'State'])
        for result in results:
            writer.writerow(result)
@app.route('/')
def index():
    return render_template("index.html")
@app.route('/scan', methods=['POST'])
def scan():
    ip_range = request.form['ip_range']
    port_range = request.form['port_range']
    results = []
    try:
        nm = nmap.PortScanner()
        if ':' in ip_range:
            nm.scan(ip_range, arguments='-6')
        else:
            nm.scan(ip_range, port_range)
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    results.append([host, port, nm[host][proto][port]['state']])
                    check_vulnerabilities(host, port)
        save_results(results, 'scan_results.csv')
    except Exception as e:
            logging.exception("an error occured during the scan:%s")
    return render_template("results.html", results=results)

if __name__ == "__main__":
    app.run(debug=True)
