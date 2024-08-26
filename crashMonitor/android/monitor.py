import glob
import os
import config
import errno
import time
import logging
import subprocess
import argparse
from adb_shell.adb_device import AdbDeviceTcp
from adb_shell.auth.sign_pythonrsa import PythonRSASigner
from adb_shell.auth.keygen import keygen
from const import *

from logger import CustomFormatter
TOMBSTONE_PATH = '/data/tombstones'

crash_signals = [
    "signal 11", "signal 6", "signal 5", "signal 9",
    "Crash", "Fatal", "end of stack trace",
    "SIGSEGV", "SIGILL", "SIGFPE", "SIGBUS", "SIGKILL", "FORTIFY"
]

logger = logging.getLogger("crash_monitor")
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(CustomFormatter())
logger.addHandler(ch)

class AndroidMonitor:
    def __init__(self, device_ip, device_port, monitor_ip, monitor_port, adbkey_path):
        self.device = None
        self.signer = None
        self.crash_cnt = 0
        self.last_crashed_time = 0
        self.DEVICE_IP = device_ip
        self.DEVICE_PORT = device_port
        self.MONITOR_IP = monitor_ip
        self.MONITOR_PORT = monitor_port
        self.ADBKEY_PATH = adbkey_path

    def parse_pkt(self, pkt):
        rfcomm_pkt = pkt[9:]
        address = rfcomm_pkt[0]
        control = rfcomm_pkt[1]
        payload = rfcomm_pkt[2:-1]
        fcs = rfcomm_pkt[-1]

        if control & CONTROL_SABM == CONTROL_SABM:
            TYPE = 'SABM'
        elif control & CONTROL_UA == CONTROL_UA:
            TYPE = 'UA'
        elif control & CONTROL_DM == CONTROL_DM:
            TYPE = 'DM'
        elif control & CONTROL_DISC == CONTROL_DISC:
            TYPE = 'DISC'
        elif control & CONTROL_UIH == CONTROL_UIH:
            TYPE = 'UIH'

        return address, TYPE, payload, fcs

    def get_latest_file(self, path):
        list_of_files = glob.glob(path)
        return max(list_of_files, key=os.path.getctime)

    def open_adbkey(self):
        if not os.path.isfile(self.ADBKEY_PATH):
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), self.ADBKEY_PATH)
        
        try:
            with open(self.ADBKEY_PATH) as f:
                try:
                    priv = f.read()
                except (IOError, OSError):
                    logger.error('Error Reading to privkey')
        except (PermissionError, OSError):
            logger.error('Error opening privkey')

        try:
            with open(self.ADBKEY_PATH + '.pub') as f:
                try:
                    pub = f.read()
                except (IOError, OSError):
                    logger.error('Error Reading to pubkey')
                    
        except (PermissionError, OSError):
            logger.error('Error opening pubkey')
        self.signer = PythonRSASigner(pub, priv)

    def adbkey_gen(self):
        keygen(self.ADBKEY_PATH)

    def connect(self, ip, port):
        self.device = AdbDeviceTcp(ip, port, default_transport_timeout_s=9.)
        self.device.connect(rsa_keys=[self.signer], auth_timeout_s=9.)
    
    def get_bluetooth_log(self):
        proc = subprocess.Popen(f"nc -l {self.MONITOR_PORT} > btsnoop_hci.log && echo 'success'", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        res = self.device.shell(f"su 0 -c 'cat /data/misc/bluetooth/logs/btsnoop_hci.log | nc -v {self.MONITOR_IP} {self.MONITOR_PORT}'")  
        stdout, stderr = proc.communicate()
        return res

    def get_crash_log(self):
        res = self.device.shell('logbat -b crash | echo "logcat"')
        return res

    def is_crashed(self):
        log = self.get_crash_log()
        for signal in crash_signals:    
            if signal in log:
                self.device.shell('logcat -b all -c') # clear logcat
                return True
            
        return False
    
    def save_crash_pkt(self, pkts):
        crashed_pkt = f'./crashes/crash_{self.last_crashed_time}.txt'
        pkt_info = {}
        ret = ''
        for pkt in pkts:
            address, TYPE, payload, fcs = self.parse_pkt(pkt)
            pkt_info['protocol'] = 'RFCOMM'
            pkt_info['type'] = TYPE
            pkt_info['payload'] = payload.hex()
            pkt_info['address'] = address.hex()
            pkt_info['fcs'] = fcs.hex()
            pkt_info['sended_time'] = self.last_crashed_time
            pkt_info['no'] = self.crash_cnt
            ret += str(pkt_info)+'\n'

        with open(crashed_pkt, 'w') as f:
            f.write(ret)

        self.crash_cnt += 1

    def run(self):
        self.adbkey_gen()
        self.open_adbkey()
        self.connect(self.DEVICE_IP, int(self.DEVICE_PORT))
        start = time.time()
        while True:
            end = time.time()
            if '[open]' in self.get_bluetooth_log():
                if end - start > 60:
                    print(f'start : {start}, end : {end}')
                    with open(f'./log/btsnoop_{str(int(end))}.log', 'wb') as f:
                        f.write(open('./btsnoop_hci.log', 'rb').read())
                    start = end
            if self.is_crashed():
                print('[*] crashed!')
            time.sleep(3)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Android Packet Monitor')
    parser.add_argument('--device_ip', required=True)
    parser.add_argument('--device_port', required=True)
    parser.add_argument('--monitor_ip', required=True)
    parser.add_argument('--monitor_port', required=True)
    parser.add_argument('--adbkey_path', required=True)
    args = parser.parse_args()

    device_ip = args.device_ip
    device_port = args.device_port
    monitor_ip = args.monitor_ip
    monitor_port = args.monitor_port
    adbkey_path = args.adbkey_path

    monitor = AndroidMonitor(device_ip, device_port, monitor_ip, monitor_port, adbkey_path)
    monitor.run()
