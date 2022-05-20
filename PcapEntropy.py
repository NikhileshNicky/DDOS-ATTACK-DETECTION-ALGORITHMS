from threading import Thread
from scapy.all import *
from datetime import datetime
from tkinter import *
from tkinter import messagebox
import numpy as np

class CUSUM(Thread):
    __flagsTCP = {
        'F': 'FIN',
        'S': 'SYN',
        'R': 'RST',
        'P': 'PSH',
        'A': 'ACK',
        'U': 'URG',
        'E': 'ECE',
        'C': 'CWR',
        }
    __ip_cnt_TCP = {}

    malicious = []
        
    def __init__(self, queue, text):
        Thread.__init__(self)
        self.stopped = False
        self.queue = queue
        self.text = text
        self.malicious.clear()
        self. __ip_cnt_TCP.clear()
        

    def stop(self):
        self.stopped = True

    def getMalicious(self):
        return self.malicious

    def stopfilter(self, x):
        return self.stopped

    def detect_TCPflood(self, packet, window):
        if UDP in packet:
            print("========"+str(packet))
        if TCP in packet:
            pckt_src=packet[IP].src
            pckt_dst=packet[IP].dst
            stream = pckt_src + ':' + pckt_dst

        if stream in self.__ip_cnt_TCP:
            self.__ip_cnt_TCP[stream] += 1
        else:
            self.__ip_cnt_TCP[stream] = 1

        for stream in self.__ip_cnt_TCP:
            pckts_sent = self.__ip_cnt_TCP[stream]
            src = stream.split(':')[0]
            dst = stream.split(':')[1]
            if src in window.keys():
                window[src] = window.get(src) + 1
            else:
                window[src] = 1
            if len(window) >= 5:
                entropy = []
                for key,value in window.items():
                    entropy.append(value)
                value = np.cumsum(entropy)
                if value[0] > 5:
                    print("CUSUM with attack : "+str(value))
                    self.text.insert(END,"Possible TCP-SYN-Flood Attack from %s --> %s --> %s\n"%(src,dst,str(pckts_sent)))
                    self.malicious.append(np.sum(value))
                else:
                    self.malicious.append(np.sum(value))
                    print("CUSUM without attack : "+str(value))
                    print(END,"Normal traffic from %s --> %s --> %s\n"%(src,dst,packet.ttl))
                window.clear()
            

    def process(self, queue):
        self.malicious.clear()
        window = {}
        while not queue.empty():
            pkt = queue.get()
            if IP in pkt:
                pckt_src=pkt[IP].src
                pckt_dst=pkt[IP].dst
                #print("IP Packet: %s  ==>  %s  , %s"%(pckt_src,pckt_dst,str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))), end=' ')

            if TCP in pkt:
                src_port=pkt.sport
                dst_port=pkt.dport
                #print(", Port: %s --> %s, "%(src_port,dst_port), end='')
                #print([__flagsTCP[x] for x in pkt.sprintf('%TCP.flags%')])
                self.detect_TCPflood(pkt,window)
        queue.empty()        
        messagebox.showinfo("CUSUM Based Attack Detection","CUSUM Based Attack Detection : "+str(len(self.getMalicious())))


    def run(self):
        print("Sniffing started. ")
        self.process(self.queue)

        
