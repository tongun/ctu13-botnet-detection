isDdos = True

if isDdos:
    from config_ddos import *
else:
    from config_neris import *

# ports filtered based on data from scenario 8
OTHER_PORT = -1
KNOWN_PORTS = [1, 3, 8, 10, 21, 22, 25, 53, 80, 110, 123, 135, 138, 161, 443, 445, 993, OTHER_PORT]
KNOWN_PORTS_NUMERIC = [1, 3, 8, 10, 21, 22, 25, 53, 80, 110, 123, 135, 138, 161, 443, 445, 993]

SMOTE_RATIO = 0.9
WINDOW_SEC = 60

