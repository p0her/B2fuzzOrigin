import pyshark
import subprocess
import logging
import time
from const import *
from logger import CustomFormatter

logger = logging.getLogger("crash_monitor")
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(CustomFormatter())
logger.addHandler(ch)

STATUS_ACTIVE = 1
STATUS_FAILED = 0

SIGSEGV = 11
SIGKILL = 9
SIGABRT = 6
SIGTRAP = 5
SIGILL = 4
SIGFPE = 8
SIGBUS = 7

crash_signals = [SIGSEGV, SIGABRT, SIGKILL, SIGTRAP, SIGILL, SIGFPE, SIGBUS]

class LinuxMonitor:
    def __init__(self, bt_interface):
        self.capture = pyshark.LiveCapture(interface=bt_interface, display_filter='btrfcomm', use_json=True, include_raw=True)
        self.crash_cnt = 0
        self.last_crashed_time = 0

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

    def parse_systemd_status(self, log):
        return int(log.split('status=')[1].split('/')[0])
    
    def parse_id(self, log):
        return int(log.split('bluetoothd[')[1].split('/')[0].split(']')[0])
    
    def get_service_status(self):
        popen = subprocess.Popen('systemctl is-failed bluetooth.service', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout,stderr = popen.communicate()
        if stdout.lower().strip() == b'failed':
            return STATUS_FAILED
        elif stdout.lower().strip() == b'active':
            return STATUS_ACTIVE
        
    def clear_syslog(self):
        subprocess.Popen(f'journalctl --vaccum-time=1s', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1)
        subprocess.Popen(f'journalctl --vaccum-time=2w', shell=True)

    def save_coredump(self, pid):
        coredump_popen  = subprocess.Popen(f'coredumpctl dump {pid}', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        coredump_popen_stdout, coredump_popen_stderr = coredump_popen.communicate()
        crashed_coredump = f'./crashes/crash_{self.last_crashed_time}.core'
        with open(crashed_coredump, 'w') as f:
            f.write(coredump_popen_stdout)
        logger.INFO('[*] coredump file is saved.')

    def get_syslog(self):
        popen = subprocess.Popen('journalctl -u bluetooth | tail -n 15', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = popen.communicate()
        syslog = stdout.decode().split('\n')
        for idx in range(len(syslog) - 1, -1, -1):
            if 'systemd' in syslog[idx]:
                status = self.parse_systemd_status(syslog[idx])
                if status in crash_signals:
                    logger.WARN('[*] SIGSEGV')
                    pid = self.parse_pid(syslog[idx-1])
                    self.save_coredump(pid)
                    break

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
        start = time.time()
        while True:
            self.capture.sniff(timeout=3)
            print(self.capture._packets)
            pkts = [pkt.get_raw_packet().hex() for pkt in self.capture._packets]
            print(pkts)
            end = time.time()
            if end - start > 60:
                logger.info('log write')
                with open(f'./log/{str(int(end))}.log', 'w') as f:
                    f.write(str(pkts))
                start = end
            
            status = self.get_service_status()
            if status == STATUS_FAILED:
                logger.INFO('Crashed!')
                self.last_crashed_time = time.time()
                self.get_syslog()
                self.save_crash_pkt(pkts)
                self.crash_cnt += 1
                self.capture._packets = []
                self.clear_syslog()
            time.sleep(3)

if __name__ == '__main__':
    monitor = LinuxMonitor('bluetooth0')
    monitor.run()
