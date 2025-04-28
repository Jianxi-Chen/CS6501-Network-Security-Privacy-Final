from time import sleep

def runTest(self, name):
        #-Q 0x01
        h1  = self.net.get('h1')
        h2  = self.net.get('h2')
        h11 = self.net.get('h11')
        h22 = self.net.get('h22')
        s3 = self.net.get('s3')
        s2 = self.net.get('s2')
        s1 = self.net.get('s1')

        print("[*] Starting iperf servers on h2, h22...")
        h2.cmd(f"iperf3 -s >&1 &")
        h22.cmd(f"iperf3 -s >&1 &")
        h2.cmd("tcpdump -i eth0 -w {}h2.pcap >&1 &".format(name))
        h1.cmd("tcpdump -i eth0 -w {}h1.pcap >&1 &".format(name))

        sleep(5)

        print("[*] Starting iperf client: h1 -> h2 (240s)")
        h1.cmd(f"bash ./test_script.sh -s 10.0.2.2 -d 240 -c {name}h2 >&1 &")
        sleep(70)

        print("[*] Starting iperf client: h11 -> h22 (90s)")
        h11.cmd(f"bash ./test_script.sh -s 10.0.2.22 -d 90 -c {name}h22 >&1 &")
        sleep(30)
        
        s3.cmd('echo "table_add MyEgress.ecn_action_table MyEgress.ecn_attack_0_to_1 2 =>" | simple_switch_CLI --thrift-port 9092')
        # s3.cmd('echo "table_add MyEgress.ecn_action_table MyEgress.ecn_attack_0_to_1 3 =>" | simple_switch_CLI --thrift-port 9092')
        print("[*] Adding P4 switch attack_rule")

        sleep(30)
        s1.cmd('echo "table_add MyEgress.ecn_action_table MyEgress.ecn_attack_react 4 =>" | simple_switch_CLI --thrift-port 9090')
        # s2.cmd('echo "table_add MyEgress.ecn_action_table MyEgress.ecn_attack_react 4 =>" | simple_switch_CLI --thrift-port 9091')

        sleep(125)
        print("[*] Stopping script ...")
        h2.cmd("pkill -f 'iperf3'")
        h22.cmd("pkill -f 'iperf3'")
        h2.cmd("pkill -f 'tcpdump'")
        h1.cmd("pkill -f 'tcpdump'")
        print("[*] Test finished. iperf & ping logs are in results")