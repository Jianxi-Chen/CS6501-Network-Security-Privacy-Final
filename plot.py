import json
import matplotlib.pyplot as plt
import os
import sys

# Directory for saving plots
PLOT_DIR = "plots"
RESULTS_DIR = "results"

def parse_iperf_results(filename):
    with open(filename) as f:
        data = json.load(f)
    intervals = data['intervals']
    times = [interval['sum']['end'] for interval in intervals]
    bitrates = [interval['sum']['bits_per_second'] / 1e6 for interval in intervals]  # Convert to Mbps
    retransmits = [interval['sum']['retransmits'] for interval in intervals]
    rtt = [stream['streams'][0]['rtt'] / 1000 for stream in intervals]  # Convert to ms
    return times, bitrates, retransmits, rtt

def plot_combined_results(json_files):
    plt.rcParams.update({
        'axes.titlesize': 24,  
        'axes.labelsize': 20, 
        'legend.fontsize': 16, 
        'xtick.labelsize': 16, 
        'ytick.labelsize': 16,  
        'figure.titlesize': 28,
        'font.family': 'Times New Roman'
    })

    os.makedirs(PLOT_DIR, exist_ok=True)

    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(10, 18))

    for json_file in json_files:
        json_path = os.path.join(RESULTS_DIR, json_file)
        
        if not os.path.exists(json_path):
            print(f"File '{json_file}' not found. Skipping.")
            continue

        # Extract filename without extension for labeling
        plot_name = os.path.splitext(json_file)[0]
        
        # Parse the results
        times, bitrates, retransmits, rtt = parse_iperf_results(json_path)

        # Plot throughput, retransmits, and RTT
        ax1.plot(times, bitrates, label=plot_name)
        ax2.plot(times, retransmits, label=plot_name)
        ax3.plot(times, rtt, label=plot_name)

    # Customize the plots
    ax1.set_xlabel('Time (s)')
    ax1.set_ylabel('Throughput (Mbps)')
    ax1.set_title('iperf3 Throughput over Time')
    ax1.legend()
    ax1.grid(True)

    ax2.set_xlabel('Time (s)')
    ax2.set_ylabel('Retransmits')
    ax2.set_title('iperf3 Retransmits over Time')
    ax2.legend()
    ax2.grid(True)

    ax3.set_xlabel('Time (s)')
    ax3.set_ylabel('RTT (ms)')
    ax3.set_title('iperf3 RTT over Time')
    ax3.legend()
    ax3.grid(True)

    # Adjust layout and save the figure
    plt.tight_layout()
    plt.savefig(os.path.join(PLOT_DIR, "iperf3_combined_results.png"))
    plt.close()

if __name__ == "__main__":
    # Get JSON file names from command line arguments
    if len(sys.argv) > 1:
        json_files = sys.argv[1:]
    else:
        # If no files provided, graph all JSON files in the results directory
        json_files = [f for f in os.listdir(RESULTS_DIR) if f.endswith(".json")]
    
    plot_combined_results(json_files)
