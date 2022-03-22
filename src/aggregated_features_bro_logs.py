import csv
import sys
import os
from collections import OrderedDict

# config.py
from config import *

INT_MAX = sys.maxsize
PORTS_NUM = len(KNOWN_PORTS)
STAT_FEATURES_NUM = 18  # features for bytes, packets, duration, protocol

def new_values(cur_value, min, max, sum):
    if cur_value < min:
        min = cur_value
    if cur_value > max:
        max = cur_value
    return [sum + cur_value, min, max]


def append_port_to_feature_names(names_list, port):
    ret = []
    for name in names_list:
        if port == -1:
            port = 'OTHER'
        ret.append(name + '_' + str(port))
    return ret


def print_dictionary(dict_for_window, writer, aggregate_t, botnet_ips, ddos, info):
    [botnet_num, background_num, rows_num_2] = info

    for ip_i in dict_for_window:
        attack = False
        if not ddos:
            attack = True
        if ddos and not fineGrain:
            attack = True

        output_line = []

        for port_j in dict_for_window[ip_i]:
            features = dict_for_window[ip_i][port_j]

            # for internal src_ip
            # output_line.append([port_j]) # debug only
            output_line.extend(features[0])  # aggregates
            output_line.append(len(features[2]))  # external ips count
            output_line.append(len(features[4]))  # source ports count
            output_line.append(len(features[6]))  # destination ports count

            # for internal dst_ip
            output_line.extend(features[1])  # aggregates
            output_line.append(len(features[3]))  # external ips count
            output_line.append(len(features[5]))  # source ports count
            output_line.append(len(features[7]))  # destination ports count

            # for ddos fine-grain, we need both the internal ip to be a BOTNET
            # and also the victim ip to be one of the dest_ips
            if ddos and fineGrain and victim_external in features[2]:
                    attack = True

        if ip_i in botnet_ips and attack:  # todo: labeling to be replaced, this is just for CTU13
            label = 'BOTNET'
            botnet_num = botnet_num + 1
        else:
            label = 'BACKGROUND'
            background_num = background_num + 1

        output_line.extend([label, str(aggregate_t), ip_i])
        # print(output_line)
        writer.writerow(output_line)
        rows_num_2 = rows_num_2 + 1

    info = [botnet_num, background_num, rows_num_2]
    return info


def construct_header():
    header_src = [  # for internal src_ip
                 'bytes_in_sum_s', 'bytes_in_min_s', 'bytes_in_max_s',
                 'bytes_out_sum_s', 'bytes_out_min_s', 'bytes_out_max_s',
                 'pkts_in_sum_s', 'pkts_in_min_s', 'pkts_in_max_s',
                 'pkts_out_sum_s', 'pkts_out_min_s', 'pkts_out_max_s',
                 'duration_sum_s', 'duration_min_s', 'duration_max_s',
                 'tcp_sum_s', 'udp_sum_s', 'icmp_sum_s',
                 'distinct_external_ips_s', 'distinct_src_port_s', 'distinct_dst_port_s']

    header_dst = [  # for internal dst_ip
                 'bytes_in_sum_d', 'bytes_in_min_d', 'bytes_in_max_d',
                 'bytes_out_sum_d', 'bytes_out_min_d', 'bytes_out_max_d',
                 'pkts_in_sum_d', 'pkts_in_min_d', 'pkts_in_max_d',
                 'pkts_out_sum_d', 'pkts_out_min_d', 'pkts_out_max_d',
                 'duration_sum_d', 'duration_min_d', 'duration_max_d',
                 'tcp_sum_d', 'udp_sum_d', 'icmp_sum_d',
                 'distinct_external_ips_d', 'distinct_src_port_d', 'distinct_dst_port_d']
    header_end = ['label', 'window_timestamp', 'internal_ip']

    header = []
    for i in range(PORTS_NUM):
        hs = append_port_to_feature_names(header_src, KNOWN_PORTS[i])
        header.extend(hs)

        hd = append_port_to_feature_names(header_dst, KNOWN_PORTS[i])
        header.extend(hd)

    header.extend(header_end)
    # print(header)
    return header


def aggregate_bro_logs(out_file_name='conn_log_aggregated.csv', in_file_name='extractedConnLogFeatures.csv',
                       botnet_ips=(), window=WINDOW_SEC, ddos=False):
    """
    Aggregates the conn.log based on ports for each WINDOW_SEC for each internal ip
        :param in_file_name: name of the bro conn log file in the csv format, where each row is:
        ts, uid, src_ip, src_port, dst_ip, dst_port, protocol, service, duration, bytes_outgoing, bytes_incoming, state, packets_outgoing, packets_incoming

        :param out_file_name: Resulting file is a csv where each row represents the traffic features for each of the destination
        'KNOWN_PORTS'(specified in config.py) for a source node (internal) within the WINDOW_SEC: (a sequence of these 21 features)
        bytes_in_sum, bytes_in_min, bytes_in_max, bytes_out_sum, bytes_out_min, bytes_out_max, pkts_in_sum, pkts_in_min, pkts_in_max,
        pkts_out_sum, pkts_out_min,pkts_out_max, duration_sum, duration_min, duration_max, tcp_sum, udp_sum, icmp_sum, distinct_dst_ips,
        distinct_src_port, distinct_dst_port

        :param botnet_ips: used for labeling malicious IPs:
        :param ddos: used for finer grained labeling, in this case the victim IP is also used:
    """

    rows_num_1 = 0
    rows_num_2 = 0
    int_num = 0
    int_vict_num = 0
    int_novict_num = 0
    ext_num = 0
    botnet_num = 0
    background_num = 0

    os.makedirs(os.path.dirname(out_file_name), exist_ok=True)

    with open(in_file_name, 'r') as csvIn, open(out_file_name, mode='w+') as csvOut:
        reader = csv.reader(csvIn, delimiter=',')
        next(reader, None)  # skip the header

        writer = csv.writer(csvOut, delimiter=',')
        header = construct_header()
        writer.writerow(header)

        aggregate_t = None
        dict_for_window = {}

        for row in reader:
            rows_num_1 = rows_num_1 + 1

            # replace missing data with 0
            row = [0 if elem == '-' else elem for elem in row]

            ts, uid, src_ip, src_port, dst_ip, dst_port, protocol, service, duration, bytes_outgoing, bytes_incoming, \
                state, packets_outgoing, packets_incoming = row
            ts, duration = float(ts), float(duration)
            src_port, dst_port, bytes_outgoing, bytes_incoming, packets_outgoing, packets_incoming = \
                int(src_port), int(dst_port), int(bytes_outgoing), int(bytes_incoming), \
                int(packets_outgoing), int(packets_incoming)

            if aggregate_t is None:
                aggregate_t = int(int(ts) // window * window)

            cur_aggregate_t = int(int(ts) // window * window)

            if cur_aggregate_t != aggregate_t:  # time window changed
                if dict_for_window:
                    info = [botnet_num, background_num, rows_num_2]
                    [botnet_num, background_num, rows_num_2] = \
                        print_dictionary(dict_for_window, writer, aggregate_t, botnet_ips, ddos, info)

                    dict_for_window = {}
                aggregate_t = None

            # ignore internal to internal traffic, except for ddos attack
            if src_ip.startswith(INTERNAL) and dst_ip.startswith(INTERNAL):
                int_num = int_num + 1
                # if ddos and fineGrain and dst_ip == victim_ip:
                if ddos and dst_ip == victim_ip:
                    # print("victim ip is internal. Will map it to an external ip.")
                    dst_ip = victim_external
                    int_vict_num = int_vict_num + 1
                else:             # ignore line
                    int_novict_num = int_novict_num + 1  # debugging
                    continue

            # ignore external to external traffic
            # should never happen, may want to throw an error
            if not src_ip.startswith(INTERNAL) and not dst_ip.startswith(INTERNAL):
                ext_num = ext_num + 1  # debugging
                continue

            if src_ip.startswith(INTERNAL):
                internal_ip = src_ip
                external_ip = dst_ip
                features_index = 0
            else:
                internal_ip = dst_ip
                external_ip = src_ip
                features_index = 1

            orig_dst_port = dst_port  # keep the original value

            # replace the port number if it falls in OTHER
            if dst_port not in KNOWN_PORTS:
                dst_port = OTHER_PORT

            # compute total bytes per protocol
            tcp_bytes, udp_bytes, icmp_bytes = (0, 0, 0)
            if protocol == 'tcp':
                tcp_bytes = bytes_outgoing + bytes_incoming 
            elif protocol == 'udp':
                udp_bytes = bytes_outgoing + bytes_incoming
            else:
                icmp_bytes = bytes_outgoing + bytes_incoming

            # initialize the dst_port dict for each src_ip
            # feature vector:
            # tcp_sum, udp_sum, icmp_sum, bytes_in_sum, bytes_in_min,
            # bytes_in_max, bytes_out_sum, bytes_out_min, bytes_out_max,
            # pkts_in_sum, pkts_in_min,pkts_in_max,pkts_out_sum, pkts_out_min,pkts_out_max,
            # duration_sum, duration_min, duration_max
            # same list of features for each link direction
            # sets = ip list, source_port list, dest_port list
            # todo: how to represent connection state or success/fail?
            if internal_ip not in dict_for_window:
                    dict_for_window[internal_ip] = OrderedDict()
                    for port in KNOWN_PORTS:
                            dict_for_window[internal_ip][port] = [[0] * STAT_FEATURES_NUM, [0] * STAT_FEATURES_NUM,
                                                                  set(), set(), set(), set(), set(), set()]

            # update the corresponding list of features for the internal ip
            # for internal src_ip update features list at index 0
            # for internal dst_ip update features list at index 1
            flist = [bytes_in_sum, bytes_in_min, bytes_in_max, bytes_out_sum, bytes_out_min, bytes_out_max,
                     pkts_in_sum, pkts_in_min, pkts_in_max, pkts_out_sum, pkts_out_min, pkts_out_max,
                     duration_sum, duration_min, duration_max,
                     tcp_sum, udp_sum, icmp_sum] = dict_for_window[internal_ip][dst_port][features_index]

            # print(flist)

            if all(v == 0 for v in flist):
                # if this is the first time we add features initialize min values
                # to something really big
                bytes_in_min = INT_MAX
                bytes_out_min = INT_MAX
                pkts_in_min = INT_MAX
                pkts_out_min = INT_MAX
                duration_min = INT_MAX

            dict_for_window[internal_ip][dst_port][features_index] = \
                new_values(bytes_incoming, bytes_in_min, bytes_in_max, bytes_in_sum) \
                + new_values(bytes_outgoing, bytes_out_min, bytes_out_max, bytes_out_sum) \
                + new_values(packets_incoming, pkts_in_min, pkts_in_max, pkts_in_sum) \
                + new_values(packets_outgoing, pkts_out_min, pkts_out_max, pkts_out_sum) \
                + new_values(duration, duration_min, duration_max, duration_sum)\
                + [tcp_sum + tcp_bytes, udp_sum + udp_bytes, icmp_sum + icmp_bytes]

            # update the set of external_ips this internal_ip connects to
            # update the first set for internal src_ip or the second set for internal dst_ip
            if external_ip not in dict_for_window[internal_ip][dst_port][features_index + 2]:
                    dict_for_window[internal_ip][dst_port][features_index + 2].add(external_ip)

            # update the sets of source ports and destination ports
            # update the corresponding set for either internal src_ip or internal dst_ip
            if src_port not in dict_for_window[internal_ip][dst_port][features_index + 4]:
                    dict_for_window[internal_ip][dst_port][features_index + 4].add(src_port)
            if orig_dst_port not in dict_for_window[internal_ip][dst_port][features_index + 6]:
                    dict_for_window[internal_ip][dst_port][features_index + 6].add(orig_dst_port)

            # print(dict_for_window[internal_ip][dst_port])

        if dict_for_window:
            info = [botnet_num, background_num, rows_num_2]
            [botnet_num, background_num, rows_num_2] = \
                print_dictionary(dict_for_window, writer, aggregate_t, botnet_ips, ddos, info)

    csvIn.close()
    csvOut.close()

    print("window, ddos: ", window, ddos)
    print("rows_num_1, rows_num_2: ", rows_num_1, rows_num_2)
    print("int_num, int_vict_num, int_novict_num, ext_num: ", int_num, int_vict_num, int_novict_num, ext_num)
    print("botnets, background: ", botnet_num, background_num)
    sys.stdout.flush()


if __name__ == '__main__':

    CONN_BRO_CSV_FILENAME = 'extractedConnLogFeatures.csv'
    for dir, botnet_ips in BOTNET_IPS.items():
        print('Scenario:', dir)
        sys.stdout.flush()
        out_file_name = os.path.join(PATH_FEATURES, dir, FILENAME_STAT)
        in_file_name = os.path.join(PATH_CONN_LOG, dir, CONN_BRO_CSV_FILENAME)
        print('Reading file:', in_file_name)
        print('Stat output file:', out_file_name)
        sys.stdout.flush()
        aggregate_bro_logs(out_file_name, in_file_name, botnet_ips, window=WINDOW_SEC, ddos=isDdos)

