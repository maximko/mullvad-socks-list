import requests
import pydig
from prettytable import PrettyTable
import flag
from random import randint
from datetime import datetime,timezone
from threading import Thread
from queue import Queue
import geoip2.database

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

geoip2_reader = geoip2.database.Reader("GeoLite2-City.mmdb")

def ip_to_timezone(ipv4):
    global geoip2_reader
    try:
        response = geoip2_reader.city(ipv4)
        timezone = response.location.time_zone
        if timezone:
            return timezone
        else:
            return None
    except:
        return None

queue = Queue()
resolved = {}
failed = {}

r = requests.get('https://api.mullvad.net/www/relays/wireguard/').json()

for host in r:
    if host['socks_name'] is not None and host['active']:
        queue.put(host['socks_name'])

total_proxies = queue.qsize()
threads = []
for i in range(0, 3):
    threads.append(Thread(target=resolver, args=(queue,resolved,failed), daemon=True))
    threads[i].start()

queue.join()

good = PrettyTable()
good.field_names = ["flag", "country", "city", "socks5", "ipv4", "ipv6", "speed", "multihop", "owned", "provider", "stboot", "hostname"]
good.align = 'l'
good.border = False

bad = PrettyTable()
bad.field_names = ["flag", "country", "city", "socks5", "ipv4", "ipv6", "speed", "multihop", "owned", "provider", "stboot", "hostname"]
bad.align = 'l'
bad.border = False

socks_ipv4_list = []
socks_timezone_list = []

for host in r:
    if host['socks_name'] is not None and host['active']:

        fl = flag.flag(host['country_code'])
        owned = '✔️' if host['owned'] else '❌'
        stboot = '✔️' if host['stboot'] else '❌'

        if host['socks_name'] in resolved:
            socks_addr = resolved[host['socks_name']]
            good.add_row([fl,
                host['country_name'],
                host['city_name'],
                socks_addr,
                host['ipv4_addr_in'],
                host['ipv6_addr_in'],
                host['network_port_speed'],
                host['multihop_port'],
                owned,
                host['provider'],
                stboot,
                host['hostname'],
            ])

            # socks and ipv4 list
            socks_ipv4_list.append('%s %s' % (socks_addr, host['ipv4_addr_in']))

            # socks and timezone list
            ip_timezone = ip_to_timezone(host['ipv4_addr_in'])
            if ip_timezone:
                socks_timezone_list.append(f'{socks_addr} {ip_timezone}')

        elif host['socks_name'] in failed:
            bad.add_row([fl,
                host['country_name'],
                host['city_name'],
                host['socks_name'],
                host['ipv4_addr_in'],
                host['ipv6_addr_in'],
                host['network_port_speed'],
                host['multihop_port'],
                owned,
                host['provider'],
                stboot,
                host['hostname'],
            ])
        else:
            break

with open('repo/mullvad-socks-list.txt', 'a') as file:
    now_utc = datetime.now(timezone.utc)
    file.write('Date: %s\n' % now_utc.strftime('%Y-%m-%d %H-%M-%S %Z'))
    file.write('Total active proxies: %s\n' % total_proxies)
    file.write(good.get_string()+ '\n')
    if len(failed) > 0:
        file.write('Failed to resovle:\n')
        file.write(bad.get_string() + '\n')

with open('repo/socks-ipv4_in-list.txt', 'a') as file:
    for item in socks_ipv4_list:
        file.write("%s\n" % item)

with open('repo/socks-timezone-list.txt', 'a') as file:
    for item in socks_timezone_list:
        file.write("%s\n" % item)