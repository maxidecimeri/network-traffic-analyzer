from scapy.all import *
import pandas as pd
import matplotlib.pyplot as plt

def capture_traffic(interface):
    packets = sniff(iface=interface, count=100)
    return packets

def analyze_packets(packets):
    df = pd.DataFrame(columns=['src', 'dst', 'proto', 'length'])
    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = pkt[IP].proto
            length = len(pkt)
            df = df.append({'src': src, 'dst': dst, 'proto': proto, 'length': length}, ignore_index=True)
    return df

def visualize_traffic(df):
    plt.figure(figsize=(10,6))
    plt.hist(df['proto'], bins=20, alpha=0.7, label='Protocol Distribution')
    plt.xlabel('Protocol')
    plt.ylabel('Frequency')
    plt.title('Protocol Distribution in Captured Traffic')
    plt.legend()
    plt.show()

if __name__ == "__main__":
    interface = input("Enter network interface to capture traffic: ")
    packets = capture_traffic(interface)
    df = analyze_packets(packets)
    visualize_traffic(df)
