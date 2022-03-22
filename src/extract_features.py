from config import *
from interevent_features_bro_logs import *
from aggregated_features_bro_logs import *
from direct_features_bro_logs import *

import os
import sys

for dir, botnet_ips in BOTNET_IPS.items():
    print('Scenario:', dir)
    sys.stdout.flush()

    if isDdos:
        if fineGrain:
            subdir_1 = 'ddos_fine'
        else:
            subdir_1 = 'ddos_coarse'
    else:
        subdir_1 = 'neris'

    in_file_name = os.path.join(PATH_CONN_LOG, dir, CONN_BRO_CSV_FILENAME)
    out_file_bro = os.path.join(PATH_FEATURES, dir, subdir_1, FILENAME_BRO)

    print('Conn bro log input file:', in_file_name)
    print('BRO output file:', out_file_bro)
    sys.stdout.flush()

    convert_bro_logs(out_file_bro, in_file_name, botnet_ips, ddos=isDdos)
    print('Finished extracting BRO features')
    sys.stdout.flush()

    for window in [10, 30, 60, 120, 240, 360, 480, 600]:
        subdir_2 = 'window_' + str(window)

        out_file_stat = os.path.join(PATH_FEATURES, dir, subdir_1, subdir_2, FILENAME_STAT)
        print('Stat output file:', out_file_stat)
        sys.stdout.flush()
        aggregate_bro_logs(out_file_stat, in_file_name, botnet_ips, window, ddos=isDdos)
        print('Finished extracting STAT features for window size ', window)
        sys.stdout.flush()

        out_file_iet = os.path.join(PATH_FEATURES, dir, subdir_1, subdir_2, FILENAME_IET)
        print('IET output file:', out_file_iet)
        sys.stdout.flush()
        get_iet_features(out_file_iet, in_file_name, botnet_ips, window, ddos=isDdos)
        print('Finished extracting IET features for window size ', window)
        sys.stdout.flush()


