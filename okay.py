import csv
import threading
import tkinter as tk
from scapy.all import sniff, IP, wrpcap
import time
import datetime
import queue
from queue import Queue, Empty
import psutil
import pythoncom
#import wmi

stop_flag = False

def packetCallback(packet):
    global writer
    global pcap_filename
    if IP in packet:
        timestamp = time.time()
        protocol = packet[IP].proto
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        packet_info = f"Timestamp: {timestamp}, Protocol: {protocol}, Source IP: {source_ip}, Destination IP: {destination_ip}, Data: {packet}"
        print(packet_info)
        writer.writerow([timestamp, protocol, source_ip, destination_ip, packet])
        wrpcap(pcap_filename, packet, append=True)


def saveAll():
    global text_areas
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    with open(f"{filename}_{timestamp}.csv", "w", newline="") as file:
        writer = csv.writer(file)
        for text_area in text_areas:
            writer.writerow([text_area.get('1.0', tk.END)])
    with open(f"{filename}_{timestamp}.log", "w") as file:
        for text_area in text_areas:
            file.write(text_area.get('1.0', tk.END))

def quitAll():
    global stop_flag
    stop_flag = True

def updateSystemInfo(text_area, queue):
    while not stop_flag:
        system_info = getSystemInfo()
        queue.put(system_info)
        time.sleep(1)

def getProcessInfo():
    process_info = f"Timestamp: {datetime.datetime.now()}, Process Information:\n"
    for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent', 'status']):
        process_info += f"PID: {proc.info['pid']}, Name: {proc.info['name']}, User: {proc.info['username']}, Memory Usage: {proc.info['memory_percent']}%, CPU Usage: {proc.info['cpu_percent']}%, Status: {proc.info['status']}\n"
    return process_info

def getSystemInfo():
    cpu_percent = psutil.cpu_percent()
    virtual_memory = psutil.virtual_memory()
    disk_usage = psutil.disk_usage('/')
    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
    system_info = f"Timestamp: {datetime.datetime.now()}, CPU Usage: {cpu_percent}%, Total Memory: {virtual_memory.total}, Available Memory: {virtual_memory.available}, Memory Usage: {virtual_memory.percent}%, Total Disk Space: {disk_usage.total}, Used Disk Space: {disk_usage.used}, Free Disk Space: {disk_usage.free}, Disk Usage: {disk_usage.percent}%, Boot Time: {boot_time}"
    return system_info

def updateProcessInfo(text_area, queue):
    while not stop_flag:
        process_info = getProcessInfo()
        queue.put(process_info)
        time.sleep(1)


def update_text_area(text_area, queue):
    while not stop_flag:
        try:
            info = queue.get_nowait()
        except Empty:
            continue
        text_area.delete('1.0', tk.END)
        text_area.insert(tk.END, info)
        text_area.see(tk.END)

def createWindow(title, update_func, queue):
    window = tk.Tk()
    window.geometry("800x600")
    window.title(title)
    text_area = tk.Text(window)
    text_area.pack(fill=tk.BOTH, expand=True)
    text_areas.append(text_area)
    threading.Thread(target=update_func, args=(text_area, queue)).start()
    def update_text_area():
        while not queue.empty():
            try:
                info = queue.get_nowait()
            except Empty:
                continue
            if isinstance(info, (list, dict)):
                info = str(info)
            text_area.insert(tk.END, info + '\n')
            text_area.see(tk.END)
        window.after(100, update_text_area)
    window.after(100, update_text_area)
    save_button = tk.Button(window, text="Save", command=saveAll)
    save_button.pack()
    quit_button = tk.Button(window, text="Quit", command=quitAll)
    quit_button.pack()
    window.mainloop()  #mainEventLoop

"""
def getPhysicalInfo():
    pythoncom.CoInitialize()
    c = wmi.WMI()
    physical_info = f"Timestamp: {datetime.datetime.now()}, Physical Information:\n"
    for port in c.Win32_SerialPort():
        physical_info += f"Device ID: {port.DeviceID}, Name: {port.Name}, Description: {port.Description}, Status: {port.Status}\n"
    pythoncom.CoUninitialize()
    return physical_info


def updatePhysicalInfo(text_area, queue):
    while not stop_flag:
        pythoncom.CoInitialize()
        physical_info = getPhysicalInfo()
        queue.put(physical_info)
        pythoncom.CoUninitialize()
        time.sleep(1)

def physicalInfoWindow():
    createWindow("Physical Information", updatePhysicalInfo, physicalInfoQueue)
"""
def sniffWindow():
    createWindow("Packet Sniffing", sniffPackets, packetQueue)

def systemInfoWindow():
    createWindow("System Information", updateSystemInfo, systemInfoQueue)

def processInfoWindow():
    createWindow("Process Information", updateProcessInfo, processInfoQueue)

def start_sniffing(filename):
    global file
    global writer
    global pcap_filename
    global stop_flag
    file = open(f"{filename}.csv", "w", newline="")
    writer = csv.writer(file)
    pcap_filename = f"{filename}.pcap"
    sniffThread = threading.Thread(target=sniffPackets)
    sniffThread.start()
    systemInfoThread = threading.Thread(target=systemInfoWindow)
    systemInfoThread.start()
    processInfoThread = threading.Thread(target=processInfoWindow)
    processInfoThread.start()
    #physicalInfoThread = threading.Thread(target=physicalInfoWindow)
    #physicalInfoThread.start()
    try:
        while sniffThread.is_alive():
            sniffThread.join(1)
        while systemInfoThread.is_alive():
            systemInfoThread.join(1)
        while processInfoThread.is_alive():
            processInfoThread.join(1)
        #while physicalInfoThread.is_alive():
        #   physicalInfoThread.join(1)
    except KeyboardInterrupt:
        print("Terminating threads...")
        stop_flag = True
        sniffThread.join()
        systemInfoThread.join()
        processInfoThread.join()
        #physicalInfoThread.join()
        print("All threads terminated.")
    file.close()

def sniffPackets():
    while not stop_flag:
        sniff(prn=packetCallback, store=0, timeout=1)

if __name__ == "__main__":
    filename = input("Enter the output file name: ")
    text_areas = []
    systemInfoQueue = queue.Queue()
    processInfoQueue = queue.Queue()
    packetQueue = queue.Queue()
    #physicalInfoQueue = queue.Queue()
    start_sniffing(filename)