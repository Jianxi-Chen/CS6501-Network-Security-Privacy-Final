# CS6501-Network-Security-Privacy-Final

## Running in Virtual machine

### Download VM
**VM image** (Ubuntu 20.04): <https://drive.google.com/file/d/1TM7AP6qM2Hw7yUFAWJYoXpestTNSTyKD/>
**Login** – user: `p4`   password: `p4`

### Go to the specified folder
```bash
cd /home/p4/p4tutorials/exercises/ecn
```

### Create environment
```bash
sudo bash ./env.sh
```

### Compile P4 program
```bash
make
```

The script launches BMv2, generates traffic with iperf3, collects traces, and stores all artefacts under results/. To visualise the experiment: you can use `plots.py` script.


## Compile in your own P4 environment

###  Prerequisites
Bare-metal or VM with P4 tool-chain (p4c-bm2-ss, BMv2, P4Runtime)
– follow the official install guide for your OS.

Linux L4S stack (TCP Prague + DualPI2 queue discipline):
clone and compile the kernel from https://github.com/L4STeam/linux.

### Compile

Git clone this repository and locate in ecn file to compile it.

### Inject

In order to keep timing logic you need to build topology by yourselves, then inject the Mininet object (net) into `test.py`.


