import sys
import json
import requests
import socket
from datetime import datetime


alert_file = open(sys.argv[1])
alert = json.loads(alert_file.read())
alert_file.close()

agent_id = alert['agent']['id']
agent_ip = alert['agent']['ip']
agent_name = alert['agent']['name']

url = alert['data']['url']
domain = alert['data']['domain']
request_id = alert['data']['log']
domain_stats_url = f'http://127.0.0.1:5730/{domain}'

log_path = "/tmp/test-log"



def is_allowed(domain):
    with open("/var/ossec/integrations/domain-config.json", "r") as file:
        rules = json.load(file)
        
    now = datetime.now()
    current_day = now.strftime("%A")
    current_time = now.strftime("%H:%M")
    print(f"current {current_day} {current_time}")

    for rule in rules["domain_rules"]["allow"]:
        if rule["domain"] == domain:
            for schedule in rule["schedule"]:
                if current_day in schedule["days"]:
                    if schedule["start_time"] <= current_time <= schedule["end_time"]:
                        return "allow"

    for rule in rules["domain_rules"]["block"]:
        if rule["domain"] == domain or rule["domain"] == "*":
            for schedule in rule["schedule"]:
                if current_day in schedule["days"]:
                    if schedule["start_time"] <= current_time <= schedule["end_time"]:
                        return "block"

    return rules["domain_rules"]["default_action"]

def send_response(ip,id,command):
    HOST = ip
    PORT= 9999
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, PORT))
            
            if request_id:
                message = f"{command} {id}"
            else:
                message = f"{command}"
            s.sendall(message.encode("utf-8"))  
            
            response = s.recv(1024).decode("utf-8")
            return f"Server response: {response} from {ip}: {PORT} {command}\n"
    except Exception as e:
        return f"Error: {e}\n"
        
with open(log_path, "a") as log_file:
    # log_file.write(json.dumps(alert))
    log_file.write(f"agent: {agent_id} {agent_name} {agent_ip}\n")
    # log_file.write(f"url: {url}\n")
    log_file.write(f"domain: {domain}\n")
    log_file.write(f"request_id: {request_id}\n")
    # log_file.write(f"domain_stat_url: {domain_stats_url}\n")

    try:
        log_file.write(send_response(agent_ip,request_id,is_allowed(domain)))
        
        response = requests.get(domain_stats_url)
        response.raise_for_status()  # Kiểm tra mã trạng thái HTTP
        data = response.json()
        # log_file.write(f"Type of response data: {str(type(data))}\n")
        # log_file.write(f"Response data: {json.dumps(data, indent=4)}\n")
        # log_file.write(str(type(data['alerts'])))
        if 'YOUR-FIRST-CONTACT' in data['alerts']:
            socket_path = "/var/ossec/queue/sockets/queue"
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.connect(socket_path)
            custom_alert = {
                "domain": domain,
                "first-contact": True
            }
            message = f'1:domain_stats:{json.dumps(custom_alert)}'
            log_file.write(f"{message}\f")
            sock.send(message.encode())
            
            
    except requests.exceptions.RequestException as e:
        log_file.write(f"Request error: {str(e)}\n")
    except Exception as e:
        log_file.write(f"Unexpected error: {str(e)}\n")
