# neris scenarios
BOTNET_IPS = {
    '1_42':  ['147.32.84.165'],
    '2_43': ['147.32.84.165'],
    '9_50': ['147.32.84.165', '147.32.84.191', '147.32.84.192', '147.32.84.193', '147.32.84.204',
             '147.32.84.205', '147.32.84.206', '147.32.84.207', '147.32.84.208', '147.32.84.209']
}

# sample scenarios, for local testing
# BOTNET_IPS = {
#               'sample_scenario_1':  ['147.32.84.165'],
#               'sample_scenario_2': ['147.32.84.165']
# }

SUBNETS_CTU13 = ['147.32.84']
INTERNAL = '147.32.'

PATH_CONN_LOG = '/home/CTU13/'
PATH_FEATURES = '/home/CTU13/supervised/data/'
PATH_RESULTS = '/home/CTU13/supervised/results/'
# PATH_CONN_LOG = '../../pipeline'
# PATH_FEATURES = '../data'
# PATH_RESULTS = '../results'

CONN_BRO_CSV_FILENAME = 'extractedConnLogFeatures.csv'  # for neris
FILENAME_STAT = 'features_stat.csv'
FILENAME_IET = 'features_iet.csv'
FILENAME_BRO = 'features_bro.csv'




