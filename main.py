import requests
import json
import time
import os

API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')

def check_ip(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = json.loads(response.text)
        if data['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            print(f'{ip} is malicious')
            with open('malicious_ips.txt', 'a') as f:
                f.write(json.dumps(data) + '\n')
        else:
            print(f'{ip} is clean')
    else:
        print(f'Error checking {ip}: {response.text}')

ip_list = []
with open('honeypot_logs.json') as logs:
    for line in logs:
        data = json.loads(line)
        if data['eventid'] == "cowrie.session.connect":
            ip_list.append(data['src_ip'])
            
for ip in ip_list:
    check_ip(ip)
    time.sleep(15) # czekaj 15 sekund między zapytaniami, aby uniknąć limitu 4 requests/minutę
