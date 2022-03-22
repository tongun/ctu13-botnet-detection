from datetime import datetime
from classifier import *
from config import *

if __name__ == "__main__":

	# current date and time
	now = datetime.now()
	t = now.strftime("%Y-%m-%d_%Hh%Mm%Ss")

	features_default = [[FILENAME_STAT, FILENAME_IET]]
	window_default = [30]
	smote_default = [False]

	model_default = ['RandomForest', 'GradientBoosting']

	# Random Forest parameters
	rf_n = [100]  # n_estimators

	# Gradient Boosting parameters
	gb_l = [0.05]  # learning rate
	gb_n = [100]  # n_estimators
	gb_d = [3]  # tree depth

	if isDdos:
		if fineGrain:
			param1 = 'ddos_fine_'
		else:
			param1 = 'ddos_coarse_'
	else:
		param1 = 'neris_'

	# ---- Test 1: vary the window size, in seconds
	param = param1 + 'window'
	window = [1, 5, 10, 30, 60, 120, 240, 480, 600]
	model = ['RandomForest']
	# run_classifier_vary_param(param, t, features_default, window, model, smote_default,
	#						  rf_n=rf_n, gb_l=gb_l, gb_n=gb_n, gb_d=gb_d)

	# ---- Test 2: vary SMOTE -- True or False
	param = param1 + 'smote'
	smote = [True, False]
	# run_classifier_vary_param(param, t, features_default, window_default, model_default, smote)

	# ---- Test 3: vary the classifier model
	param = param1 + 'model'
	model = ['LR', 'RandomForest', 'GradientBoosting']
	# run_classifier_vary_param(param, t, features_default, window_default, model, smote_default,
	#						  rf_n=rf_n, gb_l=gb_l, gb_n=gb_n, gb_d=gb_d)

	# ---- Test 4: vary the features
	param = param1 + 'features'
	feature_files = [[FILENAME_STAT, FILENAME_IET], [FILENAME_STAT], [FILENAME_BRO]]
	# run_classifier_vary_param(param, t, feature_files, window_default, model_default, smote_default,
	#						  rf_n=rf_n, gb_l=gb_l, gb_n=gb_n, gb_d=gb_d)

	# ---- Test 5: print feature importance
	param = param1 + 'aux'
	model = ['RandomForest']
	# run_classifier_vary_param(param, t, features_default, window_default, model, smote_default,
	#						  rf_n=rf_n, gb_l=gb_l, gb_n=gb_n, gb_d=gb_d)

	# ---- Test 6: plot ROC curves
	param = param1 + 'roc'
	model = ['LR', 'RandomForest', 'GradientBoosting']
	run_classifier_vary_param(param, t, features_default, window_default, model, smote_default,
							  rf_n=rf_n, gb_l=gb_l, gb_n=gb_n, gb_d=gb_d, plot='sample_scenario_1', gen_roc_curve=True)


