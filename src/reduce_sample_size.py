import csv
import os

# config.py
# from config import *


def extract_ips(out_file_name='small_sample.csv', in_file_name='extractedConnLogFeatures.csv',
                windows_num=1, ips_list=['147.32.84.59'], lines_num=-1):
    """
    print only the lines containing the given ips from the first windows_num windows
    if lines_num=-1, print all lines, otherwise print the first lines_num only

    """
    with open(in_file_name, 'r') as csvIn, open(out_file_name, mode='w+') as csvOut:
        reader = csv.reader(csvIn, delimiter=',')
        writer = csv.writer(csvOut, delimiter=',')

        header = next(reader)
        writer.writerow(header)

        aggregate_t = None
        crt_windows_num = 0
        crt_lines_num = 0

        for row in reader:
            # ts, uid, src_ip, src_port, dst_ip, dst_port, protocol, service, duration, bytes_outgoing, bytes_incoming,\
            #     state, packets_outgoing, packets_incoming = row
            ts, uid, src_ip, src_port, dst_ip, dst_port, protocol, service, duration, bytes_outgoing, bytes_incoming,\
                state, packets_outgoing, packets_incoming = row
            ts = float(ts)

            if aggregate_t is None:
                aggregate_t = int(int(ts) // WINDOW_SEC * WINDOW_SEC)

            cur_aggregate_t = int(int(ts) // WINDOW_SEC * WINDOW_SEC)

            if cur_aggregate_t != aggregate_t:  # time window changed
                crt_windows_num += 1
                if windows_num == crt_windows_num:
                    break
                aggregate_t = None

            # ignore internal to internal traffic
            if src_ip.startswith(INTERNAL) and dst_ip.startswith(INTERNAL):
                continue

            # ignore external to external traffic
            # should never happen, may want to throw an error
            if not src_ip.startswith(INTERNAL) and not dst_ip.startswith(INTERNAL):
                continue

            if src_ip in ips_list or dst_ip in ips_list:
                writer.writerow(row)
                print(row)
                crt_lines_num += 1

            if crt_lines_num == lines_num:
                break

    csvIn.close()
    csvOut.close()


def print_windows_first_n(out_file_name='small_sample.csv', in_file_name='extractedConnLogFeatures.csv',
                       windows_num = 1):
    """
    print only the lines from the first windows_num windows
    """

    with open(in_file_name, 'r') as csvIn, open(out_file_name, mode='w+') as csvOut:
        reader = csv.reader(csvIn, delimiter=',')
        writer = csv.writer(csvOut, delimiter=',')

        header = next(reader)
        writer.writerow(header)

        aggregate_t = None
        crt_windows_num = 0

        for row in reader:
            ts, uid, src_ip, src_port, dst_ip, dst_port, protocol, service, duration, bytes_outgoing, bytes_incoming,\
                state, packets_outgoing, packets_incoming = row
            ts = float(ts)

            if aggregate_t is None:
                aggregate_t = int(int(ts) // WINDOW_SEC * WINDOW_SEC)

            cur_aggregate_t = int(int(ts) // WINDOW_SEC * WINDOW_SEC)

            if cur_aggregate_t != aggregate_t:  # time window changed
                crt_windows_num += 1
                if windows_num == crt_windows_num:
                    break
                aggregate_t = None

            # ignore internal to internal traffic
            if src_ip.startswith(INTERNAL) and dst_ip.startswith(INTERNAL):
                continue

            # ignore external to external traffic
            # should never happen, may want to throw an error
            if not src_ip.startswith(INTERNAL) and not dst_ip.startswith(INTERNAL):
                continue

            writer.writerow(row)

    csvIn.close()
    csvOut.close()


# get sample of the CTU13 data
IP_LIST = ['147.32.86.155', '147.32.86.179']
INTERNAL = '147.32'
WINDOW_SEC = 60
WINDOWS_NUM = 1
LINES_NUM = 20
directory = 'sample_scenario_1'
IN_FILENAME = 'extractedConnLogFeatures.csv'
OUT_FILENAME = 'small_sample_1.csv'


"""
# get sample of wannacry merged data
IP_LIST = ['3.110.178.105']
INTERNAL = '3.110'
WINDOW_SEC = 60
WINDOWS_NUM = 1
LINES_NUM = 10
directory = '/net/data-backedup/chase/background_uva/1day/nv/vol258/bro-anonymized-labeled-conn-logs/2019-03-01'
IN_FILENAME = 'anon.conn_tcp_udp.23:00:00-00:00:00merged_3_23_19ALL.csv'
OUT_FILENAME = 'anon.conn_tcp_udp.23:00:00-00:00:00merged_3_23_19ALL_sample.csv'
"""

infile = os.path.join(directory, IN_FILENAME)
outfile = os.path.join(directory, OUT_FILENAME)

print("From: ", infile)
print("To: ", outfile)

extract_ips(outfile, infile, WINDOWS_NUM, IP_LIST, LINES_NUM)


