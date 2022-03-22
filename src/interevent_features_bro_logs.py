import sys
import os
import csv
import numpy as np
from collections import OrderedDict

# config.py
from config import *

PORTS_NUM = len(KNOWN_PORTS)


rows_num_1 = 0
rows_num_2 = 0
int_num = 0
int_vict_num = 0
int_novict_num = 0
ext_num = 0
botnet_num = 0
background_num = 0


def append_port_to_feature_names(names_list, port):
    ret = []
    for name in names_list:
        if port == -1:
            port = 'OTHER'
        ret.append(name + '_' + str(port))
    return ret


def construct_header():
    # for internal src_ip
    header_src = ['avg_s', 'std_s', 'median_s', 'min_s', 'max_s']

    # for internal dst_ip
    header_dst = ['avg_d', 'std_d', 'median_d', 'min_d', 'max_d']

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


def compute_features(event_list):
    """
    compute average, std, median, mean and max statistics over inter-event times
    """

    # if there is a single event, initialize features with -1
    if len(event_list) < 2:
        iet_features = [-1, -1, -1, -1, -1]
    else:
        # use the numpy package to compute time between each two consecutive events in the array
        iet_features = [np.average(np.array(event_list[1:]) - np.array(event_list[:-1])),
                         np.std(np.array(event_list[1:]) - np.array(event_list[:-1])),
                         np.median(np.array(event_list[1:]) - np.array(event_list[:-1])),
                         np.min(np.array(event_list[1:]) - np.array(event_list[:-1])),
                         np.max(np.array(event_list[1:]) - np.array(event_list[:-1]))]
    return iet_features


def print_dictionary(dict_for_window, dict_dst_ips, writer, aggregate_t, botnet_ips, ddos, info):

    [botnet_num, background_num, rows_num_2] = info

    for ip_i in dict_for_window:

        output_line = []
        for port_j in dict_for_window[ip_i]:
            event_lists = dict_for_window[ip_i][port_j]

            # for internal src_ip
            iet_src_features = compute_features(event_lists[0])
            output_line.extend(iet_src_features)

            # for internal dst_ip
            iet_dst_features = compute_features(event_lists[1])
            output_line.extend(iet_dst_features)

        # for ddos fine-grain, we need both the internal ip to be a BOTNET
        # and also the victim ip to be one of the dest_ips
        attack = True
        if ddos and fineGrain and victim_external not in dict_dst_ips[ip_i]:
            attack = False

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


def get_iet_features(out_file_name='conn_log_iet.csv', in_file_name='extractedConnLogFeatures.csv', botnet_ips=(), window=WINDOW_SEC, ddos=False):
    """
    Reads the input file, saves the timestamps for each (internal ip, destination port) pair
    Computes the inter-arrival times between timestamps,
    then computes avg, std, median, min, max over these inter-arrival times
    and writes them to the output file
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
        dict_dst_ips = {}

        for row in reader:
            rows_num_1 = rows_num_1 + 1

            # replace missing data with 0
            row = [0 if elem == '-' else elem for elem in row]

            ts = float(row[0])
            src_ip = row[2]
            dst_ip = row[4]
            dst_port = int(row[5])

            src_ip = src_ip.strip()
            dst_ip = dst_ip.strip()

            if aggregate_t is None:
                aggregate_t = int(int(ts) // window * window)

            cur_aggregate_t = int(int(ts) // window * window)

            if cur_aggregate_t != aggregate_t:  # time window changed
                if dict_for_window:
                    info = [botnet_num, background_num, rows_num_2]
                    [botnet_num, background_num, rows_num_2] = \
                        print_dictionary(dict_for_window, dict_dst_ips, writer, aggregate_t, botnet_ips, ddos, info)
                    dict_for_window = {}
                    dict_dst_ips = {}
                aggregate_t = None

            # ignore internal to internal traffic, except for ddos attack
            if src_ip.startswith(INTERNAL) and dst_ip.startswith(INTERNAL):
                int_num = int_num + 1

                # if ddos and fineGrain and dst_ip == victim_ip:
                if ddos and dst_ip == victim_ip:
                    # print("victim ip is internal. Will map it to an external ip.")
                    dst_ip = victim_external
                    int_vict_num = int_vict_num + 1
                else:  # ignore line
                    int_novict_num = int_novict_num + 1
                    continue

            # ignore external to external traffic
            if not src_ip.startswith(INTERNAL) and not dst_ip.startswith(INTERNAL):
                ext_num = ext_num + 1
                continue

            if src_ip.startswith(INTERNAL):
                internal_ip = src_ip
                features_index = 0
            else:
                internal_ip = dst_ip
                features_index = 1

            # replace the port number if it falls in OTHER
            if dst_port not in KNOWN_PORTS:
                dst_port = OTHER_PORT

            # initialize the dst_port dict for each src_ip
            if internal_ip not in dict_for_window:
                dict_for_window[internal_ip] = OrderedDict()
                dict_dst_ips[internal_ip] = []
                for port in KNOWN_PORTS:
                    dict_for_window[internal_ip][port] = [[], []]

            # save the current timestamp
            dict_for_window[internal_ip][dst_port][features_index].append(ts)

            # save the dst_ip only if it is external; will use it to check the victim ip
            if features_index == 0:
                dict_dst_ips[internal_ip].append(dst_ip)
            # print(dict_for_window)

        if dict_for_window:
            info = [botnet_num, background_num, rows_num_2]
            [botnet_num, background_num, rows_num_2] = \
                print_dictionary(dict_for_window, dict_dst_ips, writer, aggregate_t, botnet_ips, ddos, info)

    csvIn.close()
    csvOut.close()

    print("rows_num_1, rows_num_2: ", rows_num_1, rows_num_2)
    print("int_num, int_vict_num, int_novict_num, ext_num: ", int_num, int_vict_num, int_novict_num, ext_num)
    print("botnets, background: ", botnet_num, background_num)
    sys.stdout.flush()


if __name__ == '__main__':
   for dir, botnet_ips in BOTNET_IPS.items():
        print('Scenario:', dir)
        sys.stdout.flush()
        out_file_name = os.path.join(PATH_FEATURES, dir, FILENAME_IET)
        in_file_name = os.path.join(PATH_CONN_LOG, dir, CONN_BRO_CSV_FILENAME)
        print('Reading file:', in_file_name)
        print('IET output file:', out_file_name)
        sys.stdout.flush()
        get_iet_features(out_file_name, in_file_name, botnet_ips, window=WINDOW_SEC, ddos=isDdos)



