from tkinter import messagebox
from tkinter import *
from tkinter.filedialog import askopenfilename
from tkinter import simpledialog
import tkinter
import numpy as np
from tkinter import filedialog
import matplotlib.pyplot as plt
from scapy.all import *
from multiprocessing import Queue
from PcapEntropy import *
from TimeBased import *

main = tkinter.Tk()
main.title("DDoS Attack Detection Algorithms Based on Entropy Computing")
main.geometry("1300x1200")

global filename
global cu_sum
global timebased

def uploadPCAP():
    global filename
    filename = filedialog.askopenfilename(initialdir = "Win_Pcap_Files")
    pathlabel.config(text=filename)
    text.delete('1.0', END)
    text.insert(END,'PCAP Signatures loaded\n')
        

def runCUSUM():
    global cu_sum
    text.delete('1.0', END)
    queue = Queue()
    packets = rdpcap(filename)
    for pkt in packets:
        queue.put(pkt)
    total_packets = queue.qsize();    
    text.insert(END,"Packets loaded to Queue\n");
    text.insert(END,"Total available packets in Queue are : "+str(queue.qsize()))
    cu_sum = CUSUM(queue,text)
    cu_sum.start()


def graph():
    unique, count = np.unique(cu_sum.getMalicious(),return_counts=True)
    unique = np.sort(count)
    unique1, count1 = np.unique(timebased.getMalicious(),return_counts=True)
    unique1 = np.sort(count1)
    plt.figure(figsize=(10,6))
    plt.grid(True)
    plt.xlabel('Time')
    plt.ylabel('Entropy')
    plt.plot(unique, 'ro-', color = 'blue')
    plt.plot(unique1, 'ro-', color = 'orange')
    plt.legend(['CUSUM', 'Time Based'], loc='upper left')
    #plt.xticks(wordloss.index)
    plt.title('CUSUM & Time Based Attack Detection Graph')
    plt.show()

def runTimeBased():
    global timebased
    text.delete('1.0', END)
    queue = Queue()
    packets = rdpcap(filename)
    for pkt in packets:
        queue.put(pkt)
    total_packets = queue.qsize();    
    text.insert(END,"Packets loaded to Queue\n");
    text.insert(END,"Total available packets in Queue are : "+str(queue.qsize()))
    timebased = TimeBased(queue,text)
    timebased.start()


def close():
    main.destroy()

font = ('times', 16, 'bold')
title = Label(main, text='DDoS Attack Detection Algorithms Based on Entropy Computing')
title.config(bg='Red', fg='white')  
title.config(font=font)           
title.config(height=3, width=120)       
title.place(x=0,y=5)

font1 = ('times', 13, 'bold')
upload = Button(main, text="Upload PCAP Dataset", command=uploadPCAP)
upload.place(x=700,y=100)
upload.config(font=font1)  

pathlabel = Label(main)
pathlabel.config(bg='lawn green', fg='white')  
pathlabel.config(font=font1)           
pathlabel.place(x=700,y=150)

cusumButton = Button(main, text="Run Cumulative Sum (CUSUM) Algorithm", command=runCUSUM)
cusumButton.place(x=700,y=200)
cusumButton.config(font=font1)

timeButton = Button(main, text="Run Time-Based Entropy Detection", command=runTimeBased)
timeButton.place(x=700,y=250)
timeButton.config(font=font1) 

graphButton = Button(main, text="Packets Comparison Graph", command=graph)
graphButton.place(x=700,y=300)
graphButton.config(font=font1)

exitButton = Button(main, text="Exit", command=close)
exitButton.place(x=700,y=350)
exitButton.config(font=font1)

font1 = ('times', 12, 'bold')
text=Text(main,height=30,width=80)
scroll=Scrollbar(text)
text.configure(yscrollcommand=scroll.set)
text.place(x=10,y=100)
text.config(font=font1)


main.config(bg='Black')
main.mainloop()
