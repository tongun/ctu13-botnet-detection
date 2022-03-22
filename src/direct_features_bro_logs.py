import csv
import os
import sys

# config.py
from config import *

def construct_header():
    header = []

    for i in KNOWN_PORTS:
        if i == -1:
            i = 'OTHER'
        ps = 'p' + str(i)
        header.append(ps)

    header.extend(['tcp', 'udp', 'icmp'])
    header.extend(['duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts'])
    header.extend(['label', 'timestamp_window', 'internal_ip'])
    # print('header: ', header)
    return header


def convert_bro_logs(out_file_name='conn_log_bro_tuples.csv', in_file_name='extractedConnLogFeatures.csv',
                     botnet_ips=(), ddos=False):
    """
    Converts bro logs to a format that can be given to a classifier.
    Port and protocol are converted to a tuple-format, e.g. (0, 1, 0, ...)
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

        known_ports_num = len(KNOWN_PORTS_NUMERIC)

        reader = csv.reader(csvIn, delimiter=',')
        next(reader, None)  # skip header

        writer = csv.writer(csvOut, delimiter=',')
        header = construct_header()
        writer.writerow(header)

        print('Botnet IPs:', botnet_ips)

        for row in reader:
            rows_num_1 = rows_num_1 + 1

            # replace missing data with 0
            row = [0 if elem == '-' else elem for elem in row]

            ts, uid, src_ip, src_port, dst_ip, dst_port, protocol, service, duration, bytes_outgoing, bytes_incoming, \
                state, packets_outgoing, packets_incoming = row

            src_ip = src_ip.strip()
            dst_ip = dst_ip.strip()

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
            # should never happen, may want to throw an error
            if not src_ip.startswith(INTERNAL) and not dst_ip.startswith(INTERNAL):
                ext_num = ext_num + 1
                continue

            if src_ip.startswith(INTERNAL):
                internal_ip = src_ip
            else:
                internal_ip = dst_ip

            # return a list such as [0, 0, ..., 1, 0, ...0]
            # mark with 1 the position of dst_port in the list of known ports
            # if dst_port is not among the known ports, put in 1 for OTHER_PORT
            dst_port = int(dst_port)
            if dst_port not in KNOWN_PORTS_NUMERIC:
                dst_port_converted = [0] * known_ports_num
                dst_port_converted.append(1)  # other_port
            else:         
                dst_port_converted = [1 if x == dst_port else 0 for x in KNOWN_PORTS_NUMERIC]
                dst_port_converted.append(0)

            # return a 3-element list where the protocol is marked with 1
            # protocol is either TCP, UDP or ICMP in this order
            # e.g. [0,1,0] for UDP
            if protocol in ['tcp', 'TCP']:
                protocol_converted = [1, 0, 0]
            elif protocol in ['udp', 'UDP']:
                protocol_converted = [0, 1, 0]
            else:  # ICMP
                protocol_converted = [0, 0, 1]

            # create the label for this row
            # for ddos fine-grain, we need both the internal ip to be a BOTNET
            # and also the victim ip to be one of the dest_ips
            attack = True
            if ddos and fineGrain and victim_external != dst_ip:
                attack = False

            if internal_ip in botnet_ips and attack:  # todo: labeling to be replaced, this is just for CTU13
                label = 'BOTNET'
                botnet_num = botnet_num + 1
            else:
                label = 'BACKGROUND'
                background_num = background_num + 1

            # create the output line with data and label
            # fields ts and internal_ip will not be given to the classifier, are here only for reference
            output_line = []
            output_line.extend(dst_port_converted)
            output_line.extend(protocol_converted)
            output_line.extend([duration, bytes_outgoing, bytes_incoming, packets_outgoing, packets_incoming])
            output_line.extend([label, ts, internal_ip])
            # print(output_line)
            writer.writerow(output_line)
            rows_num_2 = rows_num_2 + 1

        # for i, j in external_ips_list.items():
        #    print(i, ','.join(str(x) for x in j))
        #    print('\n')

    csvIn.close()
    csvOut.close()

    print("rows_num_1, rows_num_2: ", rows_num_1, rows_num_2)
    print("int_num, int_vict_num, int_novict_num, ext_num: ", int_num, int_vict_num, int_novict_num, ext_num)
    print("botnets, background: ", botnet_num, background_num)
    sys.stdout.flush()


if __name__ == "__main__":
    # CONN_BRO_CSV_FILENAME = 'small_sample.csv'
    # FILENAME_BRO = 'out_small_sample_bro.csv'

    # CONN_BRO_CSV_FILENAME = 'extractedConnLogFeatures.csv'
    # FILENAME_BRO = 'out_scenarios_bro.csv'

    for dir, botnet_ips in BOTNET_IPS.items():

        print('Scenario:', dir)
        out_file_name = os.path.join(PATH_FEATURES, dir, FILENAME_BRO)
        in_file_name = os.path.join(PATH_CONN_LOG, dir, CONN_BRO_CSV_FILENAME)
        print('Reading file:', in_file_name)
        print('Output file for running classifier directly on BRO logs:', out_file_name)
        convert_bro_logs(out_file_name, in_file_name, botnet_ips, ddos=isDdos)


