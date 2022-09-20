import requests
import pydig
from prettytable import PrettyTable
import flag
from random import randint
from datetime import datetime,timezone
from threading import Thread
from queue import Queue

def resolver(queue, resolved, failed):
    resolver = pydig.Resolver(nameservers=['1.1.1.1'])
    while True:
        item = queue.get()
        socks_addr = resolver.query(item, 'A')
        if len(socks_addr) > 0 and socks_addr is not ['']:
            resolved[item] = socks_addr[0]
        else:
            if item in failed:
                count = failed[item]
                if count < 3:
                    failed[item] = count + 1
                    queue.put(item)
            else:
                failed[item] = 1
                queue.put(item)
        #print("Left to resolve:", queue.qsize(), end="\r")
        queue.task_done()

queue = Queue()
resolved = {}
failed = {}

now_utc = datetime.now(timezone.utc)
print('Date:', now_utc.strftime('%Y-%m-%d %H-%M-%S %Z'))

r = requests.get('https://api.mullvad.net/www/relays/wireguard/').json()

for host in r:
    if host['socks_name'] is not None and host['active']:
        queue.put(host['socks_name'])

print("Total active proxies:", queue.qsize())
threads = []
for i in range(0, 3):
    threads.append(Thread(target=resolver, args=(queue,resolved,failed), daemon=True))
    threads[i].start()

queue.join()

good = PrettyTable()
good.field_names = ["flag", "country", "city", "socks", "ip", "speed", "multihop", "owned", "provider", "hostname"]
good.align = 'l'
good.border = False

bad = PrettyTable()
bad.field_names = ["flag", "country", "city", "socks", "ip", "speed", "multihop", "owned", "provider", "hostname"]
bad.align = 'l'
bad.border = False

for host in r:
    if host['socks_name'] is not None and host['active']:
        fl = flag.flag(host['country_code'])
        owned = '✔️' if host['owned'] else '❌'
        if host['socks_name'] in resolved:
            socks_addr = resolved[host['socks_name']]
            good.add_row([fl,
                host['country_name'],
                host['city_name'],
                socks_addr,
                host['ipv4_addr_in'],
                host['network_port_speed'],
                host['multihop_port'],
                owned,
                host['provider'],
                host['hostname'],
            ])
        elif host['socks_name'] in failed:
            bad.add_row([fl,
                host['country_name'],
                host['city_name'],
                host['socks_name'],
                host['ipv4_addr_in'],
                host['network_port_speed'],
                host['multihop_port'],
                owned,
                host['provider'],
                host['hostname'],
            ])
        else:
            break

print(good)
if len(failed) > 0:
    print('Failed to resovle:')
    print(bad)
