# ctu13-botnet-detection

Language: python 3.5

Dependencies: sklearn, imblearn, numpy, matplotlib, networkx, pandas

## Dataset

Dataset files are generated in the Stratosphere Lab as part of the Malware Capture Facility Project in the CVUT University, Prague, Czech Republic.

We use The CTU-13 Dataset - A Labeled Dataset with Botnet, Normal and Background traffic: https://www.stratosphereips.org/datasets-ctu13/

Stratosphere. (2015). Stratosphere Laboratory Datasets. https://www.stratosphereips.org/datasets-overview


## Feature Extraction

### extract_features.py

Uses the below scripts for each scenario in CTU13 and generates feature files.

#### aggregated_features_bro_logs.py

Processes the bro conn log in the csv format, where each row is:

ts, uid, src_ip, src_port, dst_ip, dst_port, protocol, service, duration, bytes_outgoing, bytes_incoming, state, packets_outgoing, packets_incoming

Resulting file is a csv where each row represents the traffic features for each of the destination 'KNOWN_PORTS' (specified in config.py) for a source node (internal) within the WINDOW_SEC: (a sequence of these 21 features)

bytes_in_sum, bytes_in_min, bytes_in_max, 
bytes_out_sum, bytes_out_min, bytes_out_max, 
pkts_in_sum, pkts_in_min, pkts_in_max, 
pkts_out_sum, pkts_out_min,pkts_out_max, 
duration_sum, duration_min, duration_max, 
tcp_sum, udp_sum, icmp_sum, 
distinct_dst_ips, distinct_src_port, distinct_dst_port

#### interevent_features_bro_logs.py

Uses the bro conn log csv file as input and generates a file with inter event timings features of internal nodes. Each file contains these 5 features for each internal ip grouped by destination port in KNOWN_PORTS for each WINDOW_SEC.

averave_iet, std_iet, median_iet, min_iet, max_iet

## Classification

### run_classifier.py

Top-level file, which runs different tests, with various parameters.

### classifier.py

Splits the scenarios into test and training and uses combined features on a classifier and prints results and accuracy metrics. 

#### read_combined_features.py

For each source node and time window (for each data point), it combines the features generated from the feature extraction scripts.


## config.py

Used for global variables across scripts. The observation window, the ports to be used, output file names etc. can be configured.

This can be created for different botnet scenarios. (e.g. config_ddos.py)

It specifies the scenarios (input data) and the botnets, as seen below:

#### all scenarios
BOTNET_IPS = {
		'1_42': ['147.32.84.165'],
		'2_43': ['147.32.84.165'],
		'3_44': ['147.32.84.165'],
		'5_46': ['147.32.84.165'],
		'6_47': ['147.32.84.165'],
		'7_48': ['147.32.84.165'],
		'8_49': ['147.32.84.165'],
		'9_50': ['147.32.84.165', '147.32.84.191', '147.32.84.192', 
			'147.32.84.193', '147.32.84.204', '147.32.84.205', 
			'147.32.84.206', '147.32.84.207', '147.32.84.208', '147.32.84.209'],
		'12_53': ['147.32.84.165', '147.32.84.191', '147.32.84.192'],
		'13_54': ['147.32.84.165']
		}


We decided to use the following set of 18 ports based on the observed usage in Scenario 8.

KNOWN_PORTS = [1, 3, 8, 10, 21, 22, 25, 53, 80, 110, 123, 135, 138, 161, 443, 445, 993, OTHER_PORT]
