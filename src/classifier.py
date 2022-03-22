from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.decomposition import PCA
from imblearn.over_sampling import SMOTE
from sklearn.metrics import roc_curve
from sklearn.metrics import roc_auc_score
from sklearn.metrics import precision_recall_curve
from sklearn.metrics import f1_score
from sklearn import metrics
from sklearn.metrics import average_precision_score

import csv
import gc
from numpy import *
import matplotlib
from matplotlib import pyplot
import pandas as pd

from read_combined_features import *
from config import *


matplotlib.use('Agg')


def print_feature_importance(out_file, columns, training_scenarios, feature_files, window, model_name, clf_model):

	pd.set_option('display.max_rows', None)
	s = pd.Series(clf_model.feature_importances_, index=columns)
	feat_importance = s.sort_values(ascending=False)

	file_name = out_file[:-4] + '_feature_importance' + '.txt'
	print('Writing feature importance to file: ', file_name)
	sys.stdout.flush()

	with open(file_name, 'a+') as f:
		f.write('\n\nTraining scenarios: ')
		f.write(', '.join(str(ts) for ts in training_scenarios))
		f.write('\n\nFeature files: ')
		f.write(', '.join(str(f) for f in feature_files))
		f.write('\n\nWindow: ')
		f.write(str(window))
		f.write('\n\nModel name: ')
		f.write(model_name)
		f.write('\n\nFeature importance with 6 decimals: \n')
		f.write(str(feat_importance.round(6)))
		f.write('\n\nFeature importance no cap on decimals: \n')
		f.write(str(feat_importance))

	f.close()

	print('Feature importance with 6 decimals: ')
	print(feat_importance.round(6))

	# print('Feature importance no cap on decimals: ')
	# print(str(feat_importance))
	sys.stdout.flush()


def run_with_test_data_given(out_file, columns, training_scenarios, feature_files, window,
							 test_data, train_data, model='RandomForest',
							 apply_pca=False, verbose=True, pc=5,
							 rf_n=100, gb_l=0.05, gb_n=100, gb_d=3,
							 label='label', plot='1_42', gen_roc_curve=False):

	X_train, y_train = train_data
	X_test, y_test = test_data

	if apply_pca:
		pca = PCA(n_components=pc)
		pca.fit(X_train)
		if verbose:
			print ('\tPrincipal Components:', pca.n_components_)
		X_train = pca.transform(X_train)
		X_test = pca.transform(X_test)

	print('Classifier is running:', model)
	sys.stdout.flush()
	gc.collect()

	if model is 'LR':
		# clf = LogisticRegression(random_state=10, penalty=regularization)
		clf = LogisticRegression(random_state=10, penalty='l1')
		clf.fit(X_train, y_train)
		line_color = 'g'
	elif model is 'GradientBoosting':
		# clf = GradientBoostingClassifier(learning_rate=0.1, n_estimators=100, max_depth=3, min_samples_split=2,
		# 								min_samples_leaf=1, subsample=1, max_features='sqrt', random_state=10)
		clf = GradientBoostingClassifier(learning_rate=gb_l, n_estimators=gb_n, max_depth=gb_d, max_features='sqrt',
										 random_state=10)
		clf.fit(X_train, y_train)
		line_color = 'b'
	elif model is 'RandomForest':
		# clf = RandomForestClassifier(random_state=0, n_jobs=-1, n_estimators=10, class_weight='balanced')
		clf = RandomForestClassifier(random_state=0, n_jobs=-1, n_estimators=rf_n)
		clf.fit(X_train, y_train)
		line_color = 'r'

		print('Feature importance len:', len(clf.feature_importances_))
		print('Number of trees:', len(clf.estimators_))
		sys.stdout.flush()
		print_feature_importance(out_file, columns, training_scenarios, feature_files, window, model, clf)

	else:
		print('Unknown Model:', model)
		exit()

	gc.collect()

	false_positive = 0
	false_negative = 0
	true_positive = 0
	true_negative = 0

	predictions = clf.predict(X_test)
	for i in range(len(X_test)):
		prediction = predictions[i]
		if prediction != y_test[i]:
			if prediction == 1:
				false_positive += 1
			else:
				false_negative += 1
		else:
			if prediction == 1:
				true_positive += 1
			else:
				true_negative += 1

	# predict probabilities
	probs = clf.predict_proba(X_test)
	# keep probabilities for the positive outcome only
	probs = probs[:, 1]

	# calculate ROC curve
	fpr, tpr, _ = roc_curve(y_test, probs)

	# calculate ROC AUC
	roc_auc = roc_auc_score(y_test, probs)

	# calculate precision-recall curve
	precision, recall, thresholds = precision_recall_curve(y_test, probs)

	# calculate F1 score
	f1 = f1_score(y_test, predictions)

	# calculate precision-recall AUC
	pr_auc = metrics.auc(recall, precision)

	# calculate average precision score
	ap = average_precision_score(y_test, probs)
	print('Precision_Recall: f1=%.3f auc=%.3f ap=%.3f' % (f1, pr_auc, ap))

	if gen_roc_curve and plot == label:
		# plot no skill
		pyplot.plot([0, 1], [0.5, 0.5], 'k--')

		# plot the precision-recall curve for the model
		pyplot.plot(recall, precision, line_color, label=model + ', F1=%.3f AUC=%.3f' % (f1, pr_auc))

		out_pr_plot = out_file[:-4] + '_precision_recall_' + str(label) + '.png'
		out_pr_plot_eps = out_file[:-4] + '_precision_recall_' + str(label) + '.eps'

		# pyplot.figure()
		# pyplot.xlim([0, 1])
		# pyplot.ylim([0, 1])

		pyplot.xlabel('Recall')
		pyplot.ylabel('Precision')
		pyplot.title('Precision-Recall curves')
		pyplot.legend(loc='best')
		pyplot.savefig(out_pr_plot, dpi=1600)
		pyplot.savefig(out_pr_plot_eps, format='eps', dpi=1600)
		print('plot saved:', out_pr_plot)

		"""
		# plotting ROC curves
		pyplot.plot([0, 1], [0, 1], 'k--')
		pyplot.plot(fpr, tpr, line_color, label=model + ', auc = %.3f' % roc_auc)
		out_roc_plot = out_file[:-4] + '_roc_' + str(label) + '.png'
		pyplot.xlabel('False positive rate')
		pyplot.ylabel('True positive rate')
		pyplot.title('ROC curves')
		pyplot.legend(loc='best')
		pyplot.savefig(out_roc_plot)
		print('plot saved:', out_roc_plot)
		"""

	return [true_positive, true_negative, false_positive, false_negative, roc_auc, pr_auc]


def apply_SMOTE(data):
	sm = SMOTE(random_state=12, ratio=SMOTE_RATIO)

	x_res, y_res = sm.fit_sample(data[0], data[1])

	botnet_count = 0
	normal_count = 0

	for elem in y_res:
		if elem == 0:
			normal_count += 1
		else:
			botnet_count += 1

	print('After Smote Normal:', normal_count)
	print('After Smote Botnet:', botnet_count)
	return x_res, y_res


def run_classifier_from_all_dirs(out_file, feature_files=[FILENAME_STAT,FILENAME_IET],
								 window=WINDOW_SEC, model='RandomForest', smote=False,
								 rf_n=100, gb_l=0.05, gb_n=100, gb_d=3, plot='1_42', gen_roc_curve=False):

	scenarios = list(BOTNET_IPS.keys())
	columns = get_column_names([scenarios[0]], feature_files, window)

	for i in range(len(scenarios)):
		# leave one scenarios out for testing
		test_scenario, training_scenarios = [scenarios[i]], scenarios[:i] + scenarios[i+1:]
		print('Test scenarios:', test_scenario)
		print('Training scenarios:', training_scenarios)
		sys.stdout.flush()
		if gen_roc_curve and plot != test_scenario[0]:
			continue

		gc.collect()
		train_data = read_feature_files_from_dirs(training_scenarios, feature_files, window)

		if smote:
			train_data = apply_SMOTE(train_data)
			print('Finished applying SMOTE')
			sys.stdout.flush()
		test_data = read_feature_files_from_dirs(test_scenario, feature_files, window)
		crt_results = run_with_test_data_given(out_file, columns, training_scenarios, feature_files, window,
											   train_data=train_data, test_data=test_data, model=model,
											   rf_n=rf_n, gb_l=gb_l, gb_n=gb_n, gb_d=gb_d,
											   gen_roc_curve=gen_roc_curve, label=test_scenario[0], plot=plot)
		print('Finished running classifier')
		sys.stdout.flush()
		model_name = model
		if model == 'RandomForest':
			model_name = model + "_trees" + str(rf_n)
		elif model == 'GradientBoosting':
			model_name = model + "_learn" + str(gb_l) + "_trees" + str(gb_n) + "_depth" + str(gb_d)
		write_results_to_csv(out_file, feature_files, test_scenario, training_scenarios,
							 window, model_name, smote, crt_results)


def write_results_to_csv(out_file, feature_files, test_scenario, training_scenarios,
						 window, model, smote, results):

	print('Writing results to file:', out_file)
	sys.stdout.flush()

	with open(out_file, mode='a+') as csvOut:
		writer = csv.writer(csvOut, delimiter=',')

		output_line = test_scenario   # it is only one test scenario
		output_line.append(', '.join(str(ts) for ts in training_scenarios))
		output_line.append(', '.join(str(f) for f in feature_files))
		output_line.append(window)
		output_line.append(model)
		output_line.append(smote)

		# 'True_positives', 'True_negatives', 'False_positives', 'False_negatives'
		output_line.extend(results[:-2])

		[true_positive, true_negative, false_positive, false_negative, roc_auc, pr_auc] = results

		if true_positive == 0:
			precision = 0
			recall = 0
			f1score = 0
		else:
			precision = 1.0 * true_positive / (true_positive + false_positive)
			recall = 1.0 * true_positive / (true_positive + false_negative)
			f1score = 2.0 * (precision * recall) / (precision + recall)

		accuracy = 1.0 * (true_negative + true_positive) / \
				   (true_negative + true_positive + false_negative + false_positive)

		output_line.append(precision)
		output_line.append(recall)
		output_line.append(f1score)
		output_line.append(roc_auc)
		output_line.append(pr_auc)
		output_line.append(accuracy)
		writer.writerow(output_line)
		print(output_line)
		sys.stdout.flush()

	print('Finished writing results')
	print('-------')
	sys.stdout.flush()
	csvOut.close()


def run_classifier_vary_param(param, time, feature_files, window=[30],
							  model=['RandomForest'], smote=[False],
							  rf_n=[100], gb_l=[0.05], gb_n=[100], gb_d=[3], plot='1_42', gen_roc_curve=False):
	fn = param + '_' + time + '.csv'
	out_file_name = os.path.join(PATH_RESULTS, fn)
	os.makedirs(os.path.dirname(out_file_name), exist_ok=True)

	header = ['Test_scenario', 'Train_scenarios', 'Feature_files', 'Window', 'Model', 'Smote',
			  'True_positives', 'True_negatives', 'False_positives', 'False_negatives',
			  'Precision', 'Recall', 'F1', 'ROC AUC', 'Prec-Recall AUC', 'Accuracy']

	# create the output file and write the header
	with open(out_file_name, mode='w+') as csvOut:
		writer = csv.writer(csvOut, delimiter=',')
		writer.writerow(header)
	csvOut.close()

	file_name_feat_importance = out_file_name[:-4] + '_feature_importance' + '.txt'
	f = open(file_name_feat_importance, mode='w+')
	f.close()

	for ff in feature_files:
		for w in window:
			for sm in smote:
				for cm in model:
					if cm == 'GradientBoosting':
						for gbl in gb_l:
							for gbn in gb_n:
								for gbd in gb_d:
									run_classifier_from_all_dirs(out_file=out_file_name, feature_files=ff,
																 window=w, model=cm, smote=sm,
																 gb_l=gbl, gb_n=gbn, gb_d=gbd, plot=plot,
																 gen_roc_curve=gen_roc_curve)
					elif cm == 'RandomForest':
						for rfn in rf_n:
								run_classifier_from_all_dirs(out_file=out_file_name, feature_files=ff,
															 window=w, model=cm, smote=sm,
															 rf_n=rfn, plot=plot, gen_roc_curve=gen_roc_curve)
					else:
						run_classifier_from_all_dirs(out_file=out_file_name, feature_files=ff,
													 window=w, model=cm, smote=sm, plot=plot,
													 gen_roc_curve=gen_roc_curve)

