// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */

#include <core.p4>
#include <v1model.p4>
#include "entries_determine_tcp_payload_size.p4inc"

/*************************************************************************
**************   Global Constants and Register Definitions   ************
*************************************************************************/

// Basic protocol constants
const bit<8>  TCP_PROTOCOL    = 0x06;
const bit<16> TYPE_IPV4       = 0x800;

// Table sizes
const bit<16> FLOW_TABLE_STAGE_SIZE    = 1024;
const bit<16> PACKET_TABLE_STAGE_SIZE  = 16384;

typedef bit<32> flow_sign_t;
typedef bit<32> mr_edge_t;
typedef bit<32> eack_t;
typedef bit<32> timestamp_t;
typedef bit<14> index_t;  // 1024 = 2^10
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

// To distinguish packet types (e.g., only differentiate SEQ from ACK)
const bit<1> PKT_IS_SEQ = 1;
const bit<1> PKT_IS_ACK = 1;

// Registers for maintaining MR edges and flow signatures
register<bit<1>>(1) global_flag;
register<mr_edge_t>((bit<32>)FLOW_TABLE_STAGE_SIZE)   ft_mr_right_edge;
register<mr_edge_t>((bit<32>)FLOW_TABLE_STAGE_SIZE)   ft_mr_left_edge;
register<flow_sign_t>((bit<32>)PACKET_TABLE_STAGE_SIZE) ft_flow_signature;

const int RTT_WINDOW_SIZE      = 10;
const int RTT_WINDOW_SIZE_BITS = 4;
const int RTT_TOTAL_ENTRIES    = (bit<32>)FLOW_TABLE_STAGE_SIZE * RTT_WINDOW_SIZE;

// Circular queue: store the last 10 RTT samples
register<bit<32>>(RTT_TOTAL_ENTRIES) flow_rtt_buffer;
// Circular queue: store the last 10 ECN values
register<bit<2>>(RTT_TOTAL_ENTRIES) flow_ecn_buffer;
// Write pointer for each flow [0..9]
register<bit<32>>((bit<32>)FLOW_TABLE_STAGE_SIZE) flow_rtt_ptr;
// To store sum of the last 10 RTTs
register<bit<32>>((bit<32>)FLOW_TABLE_STAGE_SIZE) flow_rtt_sum;
// Count how many of the last 10 ECN values equal 3
register<bit<32>>((bit<32>)FLOW_TABLE_STAGE_SIZE) flow_ecn_count;
// Number of RTT samples recorded
register<bit<32>>((bit<32>)FLOW_TABLE_STAGE_SIZE) flow_sample_count;
register<bit<32>>((bit<32>)FLOW_TABLE_STAGE_SIZE) flow_att_count;
register<bit<32>>((bit<32>)FLOW_TABLE_STAGE_SIZE) flow_atts_count;

/*************************************************************************
***************************** Headers ************************************
*************************************************************************/

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    diffserv;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    // 20 bytes
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  dataOffset;
    bit<3>  reserved;
    bit<1>  ns;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
}

struct metadata {
    // Packet type
    bit<1> is_seq;
    bit<1> is_ack;
    bit<32> len_pay;
    bit<10> temp_ptr;
    bit<2> attack_flag;
    // Flow signature
    flow_sign_t flow_sig;

    // MR edges for SEQ packets
    mr_edge_t mr_left;
    mr_edge_t mr_right;

    // eACK for ACK packets = tcp.ack_no
    eack_t eack;
    // Store timestamp of SEQ packet
    timestamp_t seq_timestamp;
    // Round-trip time
    timestamp_t rtt;
    // Used to store flow table / packet table indices
    index_t ft_index;
    index_t pt_index;
}

/*************************************************************************
****************************   Parser   **********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default:   accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TCP_PROTOCOL: parse_tcp;
            default:      accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
******************  Checksum Verification (Optional)  *******************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
********************  INGRESS PROCESSING  ********************************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // Calculate payload size
    action act_lookup_tcp_payload_size(bit<32> payload_size) {
        meta.len_pay = payload_size;
    }

    table tcp_payload_size_table {
        key = {
            hdr.ipv4.ihl : exact;
            hdr.ipv4.totalLen : exact;
            hdr.tcp.dataOffset : exact;
        }
        actions = {
            act_lookup_tcp_payload_size;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
        entries = {
            // Expand the macro here
            DETERMINE_TCP_PAYLOAD_SIZE_ENTRIES
        }
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action act_compute_seq_flow_mr_edges() {
        meta.mr_right = hdr.tcp.seq_no + meta.len_pay;
        meta.mr_left  = hdr.tcp.seq_no;
        ft_mr_right_edge.write((bit<32>)meta.temp_ptr, meta.mr_right);
    }

    action act_compute_ack_flow_mr_edges() {
        meta.mr_right = hdr.tcp.ack_no;
        meta.mr_left  = hdr.tcp.ack_no;
        ft_mr_right_edge.write((bit<32>)meta.temp_ptr, meta.mr_right);
        ft_mr_left_edge.write((bit<32>)meta.temp_ptr, meta.mr_left);
    }

    action hash_adr() {
        meta.flow_sig = (bit<32>)hdr.ipv4.srcAddr ^ (bit<32>)hdr.ipv4.dstAddr ^
                        (bit<32>)hdr.tcp.src_port ^ (bit<32>)hdr.tcp.dst_port;
        meta.temp_ptr  = meta.flow_sig[9:0];
    }

    action renew_seq() {
        meta.eack = meta.len_pay + hdr.tcp.seq_no;
        meta.pt_index = ((bit<32>)meta.temp_ptr ^ meta.eack)[13:0];
        meta.seq_timestamp = standard_metadata.ingress_global_timestamp[31:0];
        ft_flow_signature.write((bit<32>)meta.pt_index, meta.seq_timestamp);
    }

    action renew_ack() {
        ft_mr_left_edge.write((bit<32>)meta.temp_ptr, hdr.tcp.ack_no);
        meta.eack = hdr.tcp.ack_no;
        meta.pt_index = ((bit<32>)meta.temp_ptr ^ meta.eack)[13:0];
    }

    apply {
        // Initialize metadata
        meta.is_seq        = 0;
        meta.is_ack        = 0;
        meta.flow_sig      = 0;
        meta.mr_left       = 0;
        meta.mr_right      = 0;
        meta.eack          = 0;
        meta.seq_timestamp = 0;
        meta.rtt           = 0;
        meta.pt_index      = 0;
        meta.temp_ptr      = 0;

        if (hdr.tcp.isValid()) {
            tcp_payload_size_table.apply();
            hash_adr();
            ft_mr_right_edge.read(meta.mr_right, (bit<32>)meta.temp_ptr);
            ft_mr_left_edge.read(meta.mr_left, (bit<32>)meta.temp_ptr);

            if (meta.len_pay > 0) {
                meta.is_seq = PKT_IS_SEQ;
                if (hdr.tcp.seq_no > meta.mr_right) {
                    act_compute_seq_flow_mr_edges();
                    renew_seq();
                } else if (hdr.tcp.seq_no <= meta.mr_left) {
                    ft_mr_left_edge.write((bit<32>)meta.temp_ptr, meta.mr_right);
                }
            } else if (hdr.tcp.ack_no != 0) {
                meta.is_ack = PKT_IS_ACK;
                if (hdr.tcp.ack_no > meta.mr_left && hdr.tcp.ack_no <= meta.mr_right) {
                    renew_ack();
                    bit<32> st_time;
                    ft_flow_signature.read(st_time, (bit<32>)meta.pt_index);
                    if (st_time != 0) {
                        meta.rtt = standard_metadata.ingress_global_timestamp[31:0] - st_time;
                    }
                } else if (hdr.tcp.ack_no == meta.mr_left) {
                    act_compute_ack_flow_mr_edges();
                }
            }
        }
        ipv4_lpm.apply();
    }
}

/*************************************************************************
********************  EGRESS PROCESSING  *********************************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action ecn_attack_0_to_1() {
        hdr.ipv4.ecn = 3;
    }

    action ecn_attack_1_to_0() {
        if (hdr.ipv4.ecn == 3) {
            hdr.ipv4.ecn = 1;
        }
    }

    action ecn_attack_react() {
        bit<1> temp_att_flag;
        global_flag.read(temp_att_flag, 0);
        if (meta.attack_flag == 1 || temp_att_flag == 1) {
            hdr.ipv4.ecn = 3;
            hdr.tcp.ece = 1;
        } else if (meta.attack_flag == 2) {
            hdr.ipv4.ecn = 1;
            hdr.tcp.ece = 0;
        }
    }

    table ecn_action_table {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            ecn_attack_1_to_0;
            ecn_attack_0_to_1;
            ecn_attack_react;
            NoAction;
        }
        size = 256;
        default_action = NoAction();
    }

    apply {
        if (meta.rtt != 0) {
            bit<1> flag = 0;
            bit<32> sample_cnt;
            bit<32> att_cnt;
            bit<32> atts_cnt;
            flow_sample_count.read(sample_cnt, (bit<32>)meta.temp_ptr);
            flow_att_count.read(att_cnt, (bit<32>)meta.temp_ptr);
            flow_atts_count.read(atts_cnt, (bit<32>)meta.temp_ptr);

            // Read previous sum and ECN count, subtract old, add new
            bit<32> sum_val;
            bit<32> ecn_cnt;
            flow_rtt_sum.read(sum_val, (bit<32>)meta.temp_ptr);
            flow_ecn_count.read(ecn_cnt, (bit<32>)meta.temp_ptr);
            bit<1> temp_att_flag;
            global_flag.read(temp_att_flag, 0);

            if (sample_cnt > 20) {
                const bit<32> RTT_THRESHOLD = 5000;
                const bit<32> ECN_THRESHOLD = 4;
                if (meta.rtt * 10 > (sum_val + RTT_THRESHOLD) && ecn_cnt < ECN_THRESHOLD) {
                    att_cnt = att_cnt + 1;
                    meta.attack_flag = 1;
                    flag = 1;

                    temp_att_flag = 1;
                    global_flag.write(0, temp_att_flag);
                } else if (sum_val > RTT_THRESHOLD) {
                    if (meta.rtt * 10 < sum_val - RTT_THRESHOLD && ecn_cnt > ECN_THRESHOLD) {
                        atts_cnt = atts_cnt + 1;
                        meta.attack_flag = 2;
                        flag = 1;
                    }
                } else if (sum_val < RTT_THRESHOLD) {
                    if (meta.rtt * 10 < RTT_THRESHOLD - sum_val && ecn_cnt > ECN_THRESHOLD) {
                        atts_cnt = atts_cnt + 1;
                        meta.attack_flag = 2;
                        flag = 1;
                    }
                } else {
                    temp_att_flag = 0;
                    global_flag.write(0, temp_att_flag);
                }
                flow_att_count.write((bit<32>)meta.temp_ptr, att_cnt);
                flow_atts_count.write((bit<32>)meta.temp_ptr, atts_cnt);
            }

            if (flag == 0) {
                // Still in learning phase: increment sample count only
                sample_cnt = sample_cnt + 1;
                flow_sample_count.write((bit<32>)meta.temp_ptr, sample_cnt);

                // Update circular buffer with new RTT/ECN
                bit<32> rtt_offset;
                flow_rtt_ptr.read(rtt_offset, (bit<32>)meta.temp_ptr);

                // Base index for this flow
                bit<32> base_idx = ((bit<32>)meta.temp_ptr) << RTT_WINDOW_SIZE_BITS;
                bit<10> pos = (base_idx + rtt_offset)[9:0];

                // 1) Read oldest RTT/ECN from buffer
                bit<32> old_rtt;
                bit<2>  old_ecn;
                flow_rtt_buffer.read(old_rtt, (bit<32>)pos);
                flow_ecn_buffer.read(old_ecn, (bit<32>)pos);

                sum_val = sum_val - old_rtt + meta.rtt;
                if (old_ecn == 3) {
                    ecn_cnt = ecn_cnt - 1;
                }
                if (hdr.ipv4.ecn == 3) {
                    ecn_cnt = ecn_cnt + 1;
                }
                // 3) Write new RTT/ECN into buffer
                flow_rtt_buffer.write((bit<32>)pos, meta.rtt);
                flow_ecn_buffer.write((bit<32>)pos, hdr.ipv4.ecn);

                // 4) Update pointer
                rtt_offset = (rtt_offset == (RTT_WINDOW_SIZE - 1)) ? 0 : (rtt_offset + 1);
                flow_rtt_ptr.write((bit<32>)meta.temp_ptr, rtt_offset);

                // 5) Write back updated sum and ECN count
                flow_rtt_sum.write((bit<32>)meta.temp_ptr, sum_val);
                flow_ecn_count.write((bit<32>)meta.temp_ptr, ecn_cnt);
            }
        }
        ecn_action_table.apply();
    }
}

/*************************************************************************
******************  Checksum Computation (Optional)  *********************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // Recalculate the IPv4 header checksum.
        update_checksum(
            hdr.ipv4.isValid(),
            {
              hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
***************************  Deparser  ***********************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***************************  Switch  *************************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
