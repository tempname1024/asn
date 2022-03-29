#!/usr/bin/env python3

import argparse
import ipaddress
import logging
import os
import socket
import sys
import sqlite3
import threading
from glob import glob

import git

logging.basicConfig(stream=sys.stdout, format='%(asctime)s %(message)s',
        datefmt='%m/%d/%Y %H:%M:%S')
log = logging.getLogger('asn')
log.setLevel(logging.DEBUG)

class Listener:
    def __init__(self, host, port):
        self._listen(host, port)

    def _listen(self, host, port):
        with socket.socket() as _socket:
            _socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            _socket.bind((host, port))
            _socket.listen()
            while True:
                conn, addr = _socket.accept()
                threading.Thread(target=self._handler,
                        args=(conn,addr,), daemon=True).start()

    def _handler(self, conn, addr):
        recv_data = conn.recv(1024)
        if not recv_data:
            conn.close()

        try:
            recv_data = str(recv_data, 'utf-8').strip()
        except UnicodeDecodeError:
            resp = 'could not decode query to utf-8'
        else:
            log.info(f'{addr[0]} {recv_data}')

            resp = self._get_announcements(recv_data)
            if not resp:
                resp = 'no valid hostname or IP discovered'
            else:
                resp = self._pretty(resp)
        finally:
            conn.sendall(bytes(resp, 'utf-8'))
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()

    def _get_announcements(self, recv):
        db = DB()
        hosts = set()
        try:
            ip = ipaddress.ip_address(recv)
            hosts.add(ip)
        except ValueError:
            try:
                hosts = self._resolve(recv)
            except:
                return []
        finally:
            announcements = []
            for host in hosts:
                if self._is_invalid(host):
                    return []

                n = self._get_netblock(host)
                if n:
                    announcements.extend(db.query(n))

            return announcements

    def _pretty(self, announces):
        announces = sorted(announces, key=lambda x: ipaddress.ip_network(
            x[3]).version)

        head = ('AS Number', 'Country', 'AS Name', 'Announcement')
        announces.insert(0, head)
        w = [len(max(i, key=lambda x: len(str(x)))) for i in zip(*announces)]

        out = ''
        header, data = announces[0], announces[1:]
        out += ' | '.join(format(title,
            "%ds" % width) for width, title in zip(w, header))
        out += '\n' + '-+-'.join( '-' * width for width in w ) + '\n'

        for row in data:
            out += " | ".join(format(str(cdata),
                "%ds" % width) for width, cdata in zip(w, row))
            out += '\n'

        return out

    def _resolve(self, hostname):
        info = socket.getaddrinfo(hostname, 80, proto=socket.IPPROTO_TCP)
        hosts = set()
        for i in info:
            hosts.add(i[4][0])

        return hosts

    def _is_invalid(self, ip):
        net = ipaddress.ip_network(ip)

        return net.is_loopback or net.is_private or net.is_multicast

    def _get_netblock(self, ip):
        net = None
        try:
            net = ipaddress.ip_network(ip)
        except:
            return net

        if net.version == 4:
            net = net.supernet(new_prefix=24)
        elif net.version == 6:
            net = net.supernet(new_prefix=64)

        return net

class DB:
    def __init__(self):
        self.repo_path = os.path.dirname(os.path.abspath(__file__))
        self.db_path = os.path.join(self.repo_path, 'cache.db')
        self.con = sqlite3.connect(self.db_path)

        loc = os.path.join(self.repo_path, 'location-database')
        self.dataset = os.path.join(loc, 'database.txt')

        self.overrides = []
        for p in os.walk(os.path.join(loc, 'overrides')):
            for f in glob(os.path.join(p[0], '*.txt')):
                self.overrides.append(f)

    def populate_db(self):
        with self.con:
            self.con.execute('PRAGMA foreign_keys=OFF')
            self.con.execute('DROP TABLE IF EXISTS net')
            self.con.execute('DROP TABLE IF EXISTS asn')
            self.con.execute('''
                CREATE TABLE IF NOT EXISTS asn (
                    aut_num INTEGER NOT NULL PRIMARY KEY,
                    name TEXT
                )
            ''')
            self.con.execute('''
                CREATE UNIQUE INDEX idx_aut_num ON asn(aut_num)
            ''')
            self.con.execute('''
                CREATE TABLE IF NOT EXISTS net (
                    id integer NOT NULL PRIMARY KEY,
                    aut_num INTEGER,
                    net TEXT,
                    country TEXT,
                    FOREIGN KEY(aut_num) REFERENCES asn(aut_num)
                )
            ''')
            self.con.execute('''
                CREATE UNIQUE INDEX idx_net ON net(net)
            ''')
            self.con.execute('PRAGMA foreign_keys=ON')

            for txt in self.overrides:
                self._get_entries(txt)

            self._get_entries(self.dataset)

    def update(self):
        if not self._submodule_pull():
            return False
        else:
            return True

    def _submodule_pull(self):
        repo = git.Repo(self.repo_path)

        updated = False
        for module in repo.submodules:
            module.module().git.checkout('master')

            current = module.module().head.commit
            log.info(f'current location-db commit: {current}')

            module.module().remotes.origin.pull()
            if current != module.module().head.commit:
                updated = True

        return updated

    def _get_entries(self, txt):
        with open(txt, 'r') as f:
            kv = dict()
            while True:
                try:
                    line = next(f)
                except StopIteration:
                    break

                if not line.strip() or line.strip().startswith('#'):
                    if kv:
                        # key correction for overrides; uses descr
                        if kv.get('descr'):
                            kv['name'] = kv.pop('descr')
                        self._add(kv)
                        kv = dict()

                    continue

                (k, v) = (x.strip() for x in line.split(':', 1))
                kv[k] = v

    def _add(self, kv):
        # ASN information block
        if kv.get('aut-num') and kv['aut-num'].startswith('AS'):
            self.con.execute('''
                INSERT OR REPLACE INTO asn(aut_num, name) VALUES(?,?)
            ''', (kv['aut-num'][2:], kv.get('name')))

        if kv.get('net'):
            self.con.execute('''
                INSERT OR REPLACE INTO net(aut_num, net, country)
                VALUES((SELECT aut_num FROM asn WHERE aut_num = ?),?,?)
            ''', (kv.get('aut-num'), kv.get('net'), kv.get('country')))

    def query(self, net):
        announcements = []
        while True:
            rows = self.con.execute('''
                SELECT net.aut_num, net.country, asn.name, net.net
                FROM net
                INNER JOIN asn on asn.aut_num = (
                    SELECT aut_num FROM net WHERE net = ?
                )
                WHERE net.net = ?
            ''', (str(net), str(net))).fetchall()
            if len(rows) != 0:
                announcements.extend(rows)
                break
            if net.prefixlen > 0:
                net = net.supernet()
            else:
                break

        return announcements

if __name__ == '__main__':
    desc = 'asn: map hosts to their corresponding ASN via WHOIS'
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('--host', dest='host', type=str, action='store',
                        help='IP address to listen on',
                        required=False)
    parser.add_argument('--port', dest='port', type=int, action='store',
                        help='Port to listen on',
                        required=False)
    parser.add_argument('--update', dest='update', action='store_true',
                        help='Update dataset submodule and create/populate cache',
                        required=False)
    parser.add_argument('--populate', dest='populate', action='store_true',
                        help='Create and populate cache from current dataset',
                        required=False)
    args = parser.parse_args()

    if args.host and args.port:
        listen = Listener(args.host, args.port)
    elif args.update:
        db = DB()
        log.info('checking remote repository for new dataset...')
        if db.update():
            log.info('dataset updated, creating/populating cache...')
            db.populate_db()
        else:
            log.info('no changes since last update')
    elif args.populate:
        db = DB()
        log.info('creating/populating cache...')
        db.populate_db()
    else:
        parser.print_help(sys.stderr)
