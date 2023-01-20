# Port-Scanner
a port scanner using the Flask micro-framework to create a web-based frontend for the scanner.
# Port Scanner

A simple Python script that scans a given range of IP addresses for open ports.

## Getting Started

These instructions will get you a copy of the script up and running on your local machine.

### Prerequisites

You will need to have Python 3 installed on your machine in order to run the script. You can download it from the official website: https://www.python.org/downloads/

### Installing

Clone the repository and navigate to the project directory:

git clone https://github.com/dafrabzinator/port-scanner.git
cd port-scanner
you can then proceed to run the scanner.py script it will start the flask app on 
`127.0.0.1:5000`
you can then ipput the ip range to scan 
The script uses nmap library to scan and it allows you to specify IPrange and port range, it then uses the requests module to make an API request to a hypothetical vulnerability database API and check for known vulnerability on the open ports.
the check_vulnerabilities() function takes a host and a API's endpoint for the host and port. it then parses the JSON response and prints the name and description of any vulnerabilities found.
It also uses the Flask micro-framework to create a web-based frontend for the scanner. the index() function renders a template for the index page,which contains a form for the user to enter the ip range and port range from the form and pass then to the scan_network() function, then renders a template for the results page and pass the results to it.
The script also uses the logging moduke to handle errors, it creates a log file named scanner.log and write the error message to it. the logging.exception() method is used to log the error message along with the exception. 

## Contributing

If you have any suggestions or improvements for the script, feel free to open a pull request.
