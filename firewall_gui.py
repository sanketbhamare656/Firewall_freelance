import tkinter as tk
from tkinter import messagebox
import joblib
import numpy as np

model = joblib.load("firewall_model.pkl")

def check_packet():

    src = int(src_ip.get())
    dst = int(dst_ip.get())
    port = int(port_no.get())
    protocol = int(proto.get())
    size = int(packet_size.get())

    packet = np.array0([[src,dst,port,protocol,size]])

    result = model.predict(packet)

    if result[0] == 0:
        output.config(text="Packet Allowed", fg="green")
    else:
        output.config(text="Packet Blocked", fg="red")


root = tk.Tk()
root.title("Firewall Simulator")
root.geometry("400x350")

tk.Label(root,text="Firewall Packet Filter",font=("Arial",16)).pack(pady=10)

tk.Label(root,text="Source IP").pack()
src_ip = tk.Entry(root)
src_ip.pack()

tk.Label(root,text="Destination IP").pack()
dst_ip = tk.Entry(root)
dst_ip.pack()

tk.Label(root,text="Port").pack()
port_no = tk.Entry(root)
port_no.pack()

tk.Label(root,text="Protocol (1=TCP)").pack()
proto = tk.Entry(root)
proto.pack()

tk.Label(root,text="Packet Size").pack()
packet_size = tk.Entry(root)
packet_size.pack()

tk.Button(root,text="Check Packet",command=check_packet).pack(pady=15)

output = tk.Label(root,text="",font=("Arial",14))
output.pack()

root.mainloop()
