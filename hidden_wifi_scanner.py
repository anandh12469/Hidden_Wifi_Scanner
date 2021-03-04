from scapy.all import *
from threading import Thread
import pandas
import time
import os
from math import log10

# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto", "Distance"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

hidden_ssid_aps = set()

def print_all():
    while True:
        os.system("clear")
        print(networks)
        time.sleep(0.5)

def callback(packet):
    if packet.haslayer(Dot11Beacon):
        if not packet.info:
            hidden_ssid_aps.add(packet.addr3)
            # extract the MAC address of the network
            bssid = packet[Dot11].addr2
            # get the name of it
            ssid = packet[Dot11Elt].info.decode()
            def signal():
                global dBm_AntSignal
                #os.system("clear")
                for i in range(-1,100):
                    try:
                        db_signal = {'sig':packet.dBm_AntSignal}
                    except:
                        db_signal = {'sig':"N/A"}
                time.sleep(0.5)
                return db_signal
            # extract network stats
            stats = packet[Dot11Beacon].network_stats()
            # get the channel of the AP
            channel = stats.get("channel")
            # get the crypto
            crypto = stats.get("crypto")
            x = signal()
            threading.Thread(target=signal).start()
            dbm_signal = x['sig']
            def distancee():
                for i in range(1,1000):
                    try:
                        distance_g = {'dis':-log10(3*((dbm_signal + 100)**9.9)) + 19.7}
                    except:
                        distance_g = {'dis':dbm_signal}
                time.sleep(0.5)
                return distance_g
            y = distancee()
            threading.Thread(target=distancee).start()
            distance_m = y['dis']
            distance = format(distance_m, ".1f")
            networks.loc[bssid] = (ssid, dbm_signal, channel, crypto, distance)


def change_channel():
    ch = -1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 - 1
        time.sleep(0.5)


if __name__ == "__main__":
    # interface name, check using iwconfig
    interface = "wlan0mon"
    # start the thread that prints all the networks
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()
    # start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    # start sniffing
    sniff(prn=callback, iface=interface)
