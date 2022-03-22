from numpy import *
import os
import csv
import sys
import gc
from config import *


def get_column_names(dirs, feature_files=[FILENAME_STAT,FILENAME_IET], window=WINDOW_SEC):

    columns = []

    if isDdos:
        if fineGrain:
            subdir_1 = 'ddos_fine'
        else:
            subdir_1 = 'ddos_coarse'
    else:
        subdir_1 = 'neris'

    for dir1 in dirs:
        for file in feature_files:
            if file == FILENAME_BRO:
                file_name = os.path.join(PATH_FEATURES, dir1, subdir_1, file)
            else:  # aggregate by window
                subdir_2 = 'window_' + str(window)  # subdirectory named by window size
                file_name = os.path.join(PATH_FEATURES, dir1, subdir_1, subdir_2, file)

            print('Reading column names from file:', file_name)
            sys.stdout.flush()

            with open(file_name, 'r') as f:
                reader = csv.reader(f, delimiter=',')
                header = next(reader)
                columns.extend(header[:-3])

    # print('Column names: ', columns)
    # sys.stdout.flush()
    return columns


def read_feature_files_from_dirs(dirs, feature_files=[FILENAME_STAT,FILENAME_IET], window=WINDOW_SEC):
    """
        Read the feature files given in directories and combine them
        :param dirs: the directories to read files from
        :return: combined_x, combined_y: the feature vectors for each time bin, labels
    """

    print(feature_files)

    features_dict = {}
    labels_dict = {}

    # used to check if same key is found in different files of same type of features
    # should never happen
    files_dict = {}

    if isDdos:
        if fineGrain:
            subdir_1 = 'ddos_fine'
        else:
            subdir_1 = 'ddos_coarse'
    else:
        subdir_1 = 'neris'

    for dir1 in dirs:
        for file in feature_files:
            if file == FILENAME_BRO:
                file_name = os.path.join(PATH_FEATURES, dir1, subdir_1, file)
            else:  # aggregate by window
                subdir_2 = 'window_' + str(window)  # subdirectory named by window size
                file_name = os.path.join(PATH_FEATURES, dir1, subdir_1, subdir_2, file)

            print('Reading features file:', file_name)
            sys.stdout.flush()

            with open(file_name, 'r') as f:
                reader = csv.reader(f, delimiter=',')
                next(reader, None)  # skip the header

                for features in reader:
                    label, time_bin, src_ip = features[-3:]
                    key = src_ip + time_bin

                    # in case of multiple directories
                    # make sure the aggregated files have unique keys, i.e. no overlapping time windows
                    if key in files_dict:
                        if file in files_dict[key]:
                            print('Error, duplicate key! This data should have been aggregated in the right file!')
                            exit(0)
                        else:
                            files_dict[key].append(file)
                    else:
                        files_dict[key] = [file]

                    # initialize features_dict
                    # save the label
                    if label == 'BOTNET':
                        label = 1
                    else:
                        label = 0
                    if key not in features_dict:
                        features_dict[key] = []
                        labels_dict[key] = label

                    # save the numerical features
                    numerical_features = [float(x) for x in features[:-3]]
                    features_dict[key].extend(numerical_features)

                    # make sure the one key has the same label in all files
                    if labels_dict[key] != label:
                        print('Error, labels should be the same!')
                        exit(0)

            f.close()
            print('Finished reading features file ', file_name)
            sys.stdout.flush()

    # form the input vectors for the classifier
    combined_x = []
    combined_y = []
    for key in features_dict:
        combined_x.append(features_dict[key])
        combined_y.append(labels_dict[key])

    # reclaim some memory
    files_dict.clear()
    features_dict.clear()
    labels_dict.clear()
    gc.collect()

    return combined_x, combined_y

