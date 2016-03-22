import nacl.secret
import nacl.utils
import nacl.hash
import nacl.encoding
import struct
from pathlib import Path
import binascii
from scapy.all import *
import sqlite3
import time
import random
import sched
import threading

DEFAULT_DIR = ".sloth/"
KEYS_DIR = "adtn/keys/"
DATABASE_FN = "store.db"
PACKET_SIZE = 1500
MAX_INNER_SIZE = 1466
WIRELESS_IFACE = "wlp3s0"


class aDTN():
    def __init__(self, batch_size, sending_freq, creation_rate, name):
        self.batch_size = batch_size
        self.sending_freq = sending_freq
        self.creation_rate = creation_rate
        self.name = name
        self.km = KeyManager()
        self.ms = MessageStore()
        self.sending_pool = []
        self.prepare_sending_pool()
        self.next_message = 0

    def prepare_sending_pool(self):
        if len(self.sending_pool) < 2 * self.batch_size:
            to_send = self.ms.get_messages(self.batch_size)
            for message in to_send:
                for key_id in self.km.keys:
                    iv = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
                    key = self.km.keys[key_id]
                    pkt = (aDTNPacket(init_vector=iv)/aDTNInnerPacket()/message)
                    self.sending_pool.append(pkt)
            while len(self.sending_pool) < self.batch_size:
                fake_key = self.km.get_fake_key()
                iv = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
                self.sending_pool.append((aDTNPacket(init_vector=iv)/aDTNInnerPacket())) #TODO: pass fake_key to aDTNPacket

    def send(self):
        batch = []
        sample = random.sample(self.sending_pool, self.batch_size)
        for pkt in sample:
            batch.append(Ether(dst="ff:ff:ff:ff:ff:ff", type="0xcafe") / pkt)
            self.sending_pool.remove(pkt)
        sendp(batch, iface=WIRELESS_IFACE)
        self.prepare_sending_pool()

    def process(self):
        for key in self.km.keys:
            pass
            # attempt to dissect packet
            #if it works, break and add message to self.ms

    def write_message(self):
        self.ms.add_message(self.name + str(self.next_message))
        self.next_message += 1

    def run(self):
        s = sched.scheduler(time.time, time.sleep)
        s.enter(self.sending_freq, 1, self.send)
        s.enter(-math.log(1.0 - random.random()) / self.creation_rate, 2, self.write_message)
        t_rcv = threading.Thread(target=s.run, kwargs={"blocking": True})
        t_rcv.run()
        t_snd = threading.Thread(target=sniff, kwargs={"prn": self.process, "filter": "ether proto 0xcafe"})
        t_snd.run()
        threading.Thread()


class KeyManager():
    def __init__(self):
        self.keys = dict()
        self.load_keys()

    def __del__(self):
        self.save_keys()

    def create_key(self, key_id=None):
        key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        if not key_id:
            h = nacl.hash.sha256(key, nacl.encoding.HexEncoder)
            key_id = h.decode('utf-8')[:16]
        self.keys[key_id] = key
        return key_id

    def get_fake_key(self):
        return nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

    def save_keys(self, directory=DEFAULT_DIR):
        path = Path(directory + KEYS_DIR)
        for key_id in self.keys:
            file_path = path.joinpath(key_id + ".key")
            if not file_path.exists():
                key = self.keys[key_id]
                hx = binascii.hexlify(key)
                s = hx.decode('utf-8')
                with file_path.open('w', encoding='utf-8') as f:
                    f.write(s)

    def load_keys(self, directory=DEFAULT_DIR):
        path = Path(directory + KEYS_DIR)
        for file_path in path.iterdir():
            if file_path.suffix == ".key":
                with file_path.open('r', encoding='utf-8') as f:
                    s = f.readline()
                hx = s.encode('utf-8')
                key = binascii.unhexlify(hx)
                self.keys[file_path.stem] = key


class aDTNPacket(Packet):
    name = "aDTNPacket"
    fields_desc = [BitField("init_vector", None, 128)]  # 16 bytes
                 # BitField("encrypted", None, 11744 + 128)]  # 1468+16 byte authenticator from encrypting

class aDTNInnerPacket(Packet):
    packet_len = 1500
    name = "aDTNInnerPacket"
    fields_desc = [LenField("len", default=None)]

    def post_build(self, pkt, pay):
        # add padding, will be calculated when calling show2
        # which basically builds and dissects the same packet
        pad_len = self.packet_len - len(pkt)
        return pkt + b'0' * pad_len

    def extract_padding(self, s):
        l = self.len
        return s[:l], s[l:]

class MessageStore():
    def __init__(self, size_threshold=None):
        self.size_threshold = size_threshold
        self.message_count = 0
        conn = sqlite3.connect(DEFAULT_DIR + DATABASE_FN)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM stats;")
        cursor.execute("DELETE FROM message;")
        conn.close()
        self.lock = threading.RLock()

    def add_message(self, message):
        bytes = message.encode('utf-8')
        h = nacl.hash.sha256(bytes, nacl.encoding.HexEncoder)
        idx = h.decode('utf-8')
        with self.lock:
            conn = sqlite3.connect(DEFAULT_DIR + DATABASE_FN)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM stats WHERE hash=?;", [idx])
            res = cursor.fetchall()
            now = int(time.time())
            if len(res) == 0:
                # new message
                cursor.execute("INSERT INTO stats VALUES (?, ?, ?, ?, ?, ?, ?)", [idx, now, None, None, 0, 0, None])
                cursor.execute("INSERT INTO message VALUES (?, ?)", [idx, message])
                self.message_count += 1
            else:
                h, first_seen, last_rcv, last_sent, rcv_ct, snd_ct = res[0]
                cursor.execute("UPDATE stats SET last_rcv=?, snd_ct=? WHERE hash=?", [now, rcv_ct + 1, idx])
            if self.size_threshold and self.message_count > self.size_threshold:
                self.purge(10)
            conn.close()

    def purge(self, count):
        with self.lock:
            conn = sqlite3.connect(DEFAULT_DIR + DATABASE_FN)
            cursor = conn.cursor()
            cursor.execute("SELECT hash FROM stats ORDER BY rcv_ct DESC, snd_ct DESC, last_rcv DESC")
            res = cursor.fetchmany(count)
            now = int(time.time())
            for r in res:
                idx = r[0]
                cursor.execute("DELETE FROM message WHERE hash=?", [idx])
                cursor.execute("UPDATE stats SET deleted=? WHERE hash=?", [now, idx])
            conn.close()

    def get_messages(self, count=1):
        with self.lock:
            conn = sqlite3.connect(DEFAULT_DIR + DATABASE_FN)
            cursor = conn.cursor()
            cursor.execute("SELECT hash FROM stats ORDER BY rcv_ct ASC, snd_ct ASC, last_snt ASC")
            res = cursor.fetchmany(count)
            now = int(time.time())
            messages = []
            for r in res:
                idx = r[0]
                cursor.execute("SELECT content FROM message WHERE hash=?", [idx])
                msg = cursor.fetchone()[0]
                messages.append(msg)
                cursor.execute("SELECT snd_ct FROM stats WHERE hash=?", [idx])
                snd_ct = cursor.fetchone()[0]
                cursor.execute("UPDATE stats SET last_snt=?, snd_ct=? WHERE hash=?", [now, snd_ct + 1, idx])
            conn.close()
        return messages


if __name__ == "__main__":
    batch_size = 10
    sending_freq = 30
    creation_rate = 4 * 3600
    device_name = "maxwell"
    adtn = aDTN(batch_size, sending_freq, creation_rate, device_name)
    adtn.run()