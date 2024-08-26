from scapy.packet import Packet
import random

# for time out recv
from functools import wraps
import errno
import os
import signal

from layer.rfcomm.const import RFCOMM_CONTROL

RFCOMM_EA = 1

MTU = 0xffff

def _pf(const):
    return const | (1 << 4)

class FRAME_PKT:
    def __init__(self, pkt):
        self.pkt = pkt
        self.address = ""
        self.control = ""
        self.length = ""
        self.frame_check_seq = ""
    
    def parse_pkt(self):
        self.address = self.pkt[0]
        self.control = self.pkt[1]
        if self.control == RFCOMM_CONTROL.RC_CONTROL_DISC or _pf(RFCOMM_CONTROL.RC_CONTROL_DISC) == self.control:
            return 'DISC'
        elif self.control == RFCOMM_CONTROL.RC_CONTROL_DM or _pf(RFCOMM_CONTROL.RC_CONTROL_DM) == self.control:
            return 'DM'
        elif self.control == RFCOMM_CONTROL.RC_CONTROL_SABM or _pf(RFCOMM_CONTROL.RC_CONTROL_SABM) == self.control:
            return 'SABM'
        elif self.control == RFCOMM_CONTROL.RC_CONTROL_UIH or _pf(RFCOMM_CONTROL.RC_CONTROL_UIH) == self.control:
            return 'UIH' 
        elif self.control  == RFCOMM_CONTROL.RC_CONTROL_UA or _pf(RFCOMM_CONTROL.RC_CONTROL_UA) == self.control:
            return 'UA'
        else:
            return None

def timeout(seconds=10, error_message=os.strerror(errno.ETIME)):
    def decorator(func):
        def _handle_timeout(signum, frame):
            raise TimeoutError(error_message)

        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.setitimer(signal.ITIMER_REAL,seconds) #used timer instead of alarm
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result
        return wraps(func)(wrapper)
    return decorator


@timeout(3)
def inter_recv(sock):
    conn_rsp = sock.recv(MTU)
    return conn_rsp, sock
