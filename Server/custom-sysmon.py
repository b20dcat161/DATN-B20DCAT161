import sys
import json
import socket
from datetime import datetime

alert_file = open(sys.argv[1])
alert = json.loads(alert_file.read())
alert_file.close()
# alert ='{"timestamp": "2024-12-24T17:11:01.074+0700", "rule": {"level": 12, "description": "Sysmon - Event 1: Process creation C:\\\\Users\\\\toandbd\\\\AppData\\\\Local\\\\Microsoft\\\\OneDrive\\\\24.226.1110.0004\\\\Microsoft.SharePoint.exe from C:\\\\Users\\\\toandbd\\\\AppData\\\\Local\\\\Microsoft\\\\OneDrive\\\\OneDriveStandaloneUpdater.exe by \\\"C:\\\\Users\\\\toandbd\\\\AppData\\\\Local\\\\Microsoft\\\\OneDrive\\\\OneDriveStandaloneUpdater.exe\\\"", "id": "61603", "firedtimes": 10, "mail": true, "groups": ["sysmon", "sysmon_event1"]}, "agent": {"id": "001", "name": "DESKTOP-P2SP5AT", "ip": "192.168.32.196"}, "manager": {"name": "DESKTOP-KU66B6S"}, "id": "1735035061.2058367", "decoder": {"name": "windows_eventchannel"}, "data": {"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "eventID": "1", "version": "5", "level": "4", "task": "1", "opcode": "0", "keywords": "0x8000000000000000", "systemTime": "2024-12-24T10:10:59.5511100Z", "eventRecordID": "177990", "processID": "2512", "threadID": "3008", "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "DESKTOP-P2SP5AT", "severityValue": "INFORMATION", "message": "\"Process Create:\r\nRuleName: -\r\nUtcTime: 2024-12-24 10:10:59.533\r\nProcessGuid: {74c5b652-88b3-676a-fb01-000000002b00}\r\nProcessId: 3956\r\nImage: C:\\Users\\toandbd\\AppData\\Local\\Microsoft\\OneDrive\\24.226.1110.0004\\Microsoft.SharePoint.exe\r\nFileVersion: 24.226.1110.0004\r\nDescription: Microsoft SharePoint\r\nProduct: Microsoft SharePoint\r\nCompany: Microsoft Corporation\r\nOriginalFileName: Microsoft.SharePoint.exe\r\nCommandLine: \"C:\\Users\\toandbd\\AppData\\Local\\Microsoft\\OneDrive\\24.226.1110.0004\\Microsoft.SharePoint.exe\" /silentConfig\r\nCurrentDirectory: C:\\Windows\\system32\\\r\nUser: DESKTOP-P2SP5AT\\toandbd\r\nLogonGuid: {74c5b652-83a3-676a-8d67-020000000000}\r\nLogonId: 0x2678D\r\nTerminalSessionId: 1\r\nIntegrityLevel: Medium\r\nHashes: MD5=AD920A6C60565DD84D18A48461EC2273,SHA256=95A2656AF949BB1720098DEC1CFDA1C9AC25153AAD7F10DC3E251039D0D3151E,IMPHASH=AF00707C6743B5E964A24AED0B519C38\r\nParentProcessGuid: {74c5b652-85bb-676a-7301-000000002b00}\r\nParentProcessId: 5076\r\nParentImage: C:\\Users\\toandbd\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe\r\nParentCommandLine: \"C:\\Users\\toandbd\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe\"\r\nParentUser: DESKTOP-P2SP5AT\\toandbd\""}, "eventdata": {"utcTime": "2024-12-24 10:10:59.533", "processGuid": "{74c5b652-88b3-676a-fb01-000000002b00}", "processId": "3956", "image": "C:\\\\Users\\\\toandbd\\\\AppData\\\\Local\\\\Microsoft\\\\OneDrive\\\\24.226.1110.0004\\\\Microsoft.SharePoint.exe", "fileVersion": "24.226.1110.0004", "description": "Microsoft SharePoint", "product": "Microsoft SharePoint", "company": "Microsoft Corporation", "originalFileName": "Microsoft.SharePoint.exe", "commandLine": "\\\"C:\\\\Users\\\\toandbd\\\\AppData\\\\Local\\\\Microsoft\\\\OneDrive\\\\24.226.1110.0004\\\\Microsoft.SharePoint.exe\\\" /silentConfig", "currentDirectory": "C:\\\\Windows\\\\system32\\\\", "user": "DESKTOP-P2SP5AT\\\\toandbd", "logonGuid": "{74c5b652-83a3-676a-8d67-020000000000}", "logonId": "0x2678d", "terminalSessionId": "1", "integrityLevel": "Medium", "hashes": "MD5=AD920A6C60565DD84D18A48461EC2273,SHA256=95A2656AF949BB1720098DEC1CFDA1C9AC25153AAD7F10DC3E251039D0D3151E,IMPHASH=AF00707C6743B5E964A24AED0B519C38", "parentProcessGuid": "{74c5b652-85bb-676a-7301-000000002b00}", "parentProcessId": "5076", "parentImage": "C:\\\\Users\\\\toandbd\\\\AppData\\\\Local\\\\Microsoft\\\\OneDrive\\\\OneDriveStandaloneUpdater.exe", "parentCommandLine": "\\\"C:\\\\Users\\\\toandbd\\\\AppData\\\\Local\\\\Microsoft\\\\OneDrive\\\\OneDriveStandaloneUpdater.exe\\\"", "parentUser": "DESKTOP-P2SP5AT\\\\toandbd"}}}, "location": "EventChannel"}'
log_path = "/tmp/test-log2"

def check_rule(description):
    config = json.loads(open('/var/ossec/integrations/config.json').read())
    for app in config["applications"]:
        if app['name'] == description:
            current_time = datetime.now().strftime("%H:%M")
            for time_range in app['allowed_times']:
                if time_range["start"] <= current_time <= time_range["end"]:
                    return 'true\n'
                
            return "false\n"
    
    return 'app ngoai danh sach\n'


def send_alert(agent,custom_alert):
    socket_path = "/var/ossec/queue/sockets/queue"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.connect(socket_path)
    message = f"1:{agent} any:{json.dumps(custom_alert)}"
    sock.send(message.encode())
    return "send mess"


try:
    with open(log_path, "a") as log_file:
        log_file.write(json.dumps(alert) + '\n')
        log_file.write(f"Alert received: {alert['agent']['id']}\n")
        # log_file.write(f"Rule: {alert['rule']['description']}\n")
        # log_file.write(f"Data: {json.dumps(alert['data']['win']['eventdata'])}\n")
        log_file.write(f"Image: {alert['data']['win']['eventdata']['image']}\n")
        log_file.write(f"User: {alert['data']['win']['eventdata']['user']}\n")
        log_file.write(f"Uctime: {alert['data']['win']['eventdata']['utcTime']}\n")
        # log_file.write(f"CommandLine: {alert['data']['win']['eventdata']['commandLine']}\n")
        # log_file.write(f"ProcessGuid: {alert['data']['win']['eventdata']['processGuid']}\n")
        log_file.write(f"ProcessId: {alert['data']['win']['eventdata']['processId']}\n")
        try: 
            log_file.write(f"Description: {alert['data']['win']['eventdata']['description']}\n")
            check = check_rule(alert['data']['win']['eventdata']['description'])
            log_file.write(check)
            if check == 'false\n':
                log_file.write('run socket\n')
                agent= f"[{alert['agent']['id']}] ({alert['agent']['name']})"
                log_file.write(f"Agent: {agent}")
                custom_alert = {
                    # "Agent":{
                    #     "Id":"001"
                    # },
                    "Pid": alert['data']['win']['eventdata']['processId'],
                    "Description": f"Application is not allow this time: {alert['data']['win']['eventdata']['description']}",
                    "Allow": False
                }
                log_file.write(send_alert(agent,custom_alert))
                
        except Exception as e:
            log_file.write(f"Unexpected error: {str(e)}\n")
            
        log_file.write('-----------------\n')
 
except Exception as e:
    with open(log_path, "a") as log_file:
        log_file.write(f"Unexpected error: {str(e)}\n")