#!/usr/bin/env python3
"""
Attack Detection using Machine Learning - Row-based approach
Each telemetry record is treated as a separate sample
Features: first 16 columns, Labels: last 2 columns (is_attacker, attack_type)
"""
import re
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest, GradientBoostingClassifier, AdaBoostClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier

# Modern gradient-boosted ensembles (added 2026-05 for Q1 reviewer coverage).
try:
    from xgboost import XGBClassifier
    HAVE_XGB = True
except ImportError:
    HAVE_XGB = False
try:
    from lightgbm import LGBMClassifier
    HAVE_LGBM = True
except ImportError:
    HAVE_LGBM = False
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold, StratifiedGroupKFold, LeaveOneGroupOut, cross_validate
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score, make_scorer
from sklearn.preprocessing import StandardScaler
from collections import Counter
import sys

def parse_log_file(filename):
    """Parse log file and extract features - each row is a sample"""
    data = []
    
    print(f"Reading log file: {filename}")
    
    with open(filename, 'r') as f:
        for line_num, line in enumerate(f, 1):
            # Extract data from log line
            # Format: Received from ('fd00::200:0:0:X', port, ...): b' timestamp,node_id,parent_id,rank,...'
            match = re.search(r"b'[\s]*([0-9,\-\s]+)'", line)
            if match:
                data_str = match.group(1).strip()
                values = [int(x.strip()) for x in data_str.split(',') if x.strip()]
                
                if len(values) >= 18:  # Ensure we have all fields
                    # Features: first 16 columns (0-15)
                    features = {
                        'timestamp': values[0],
                        'node_id': values[1],
                        'parent_id': values[2],
                        'rank': values[3],
                        'buf_occupancy': values[4],
                        'dio_sent': values[5],
                        'dao_sent': values[6],
                        'dis_sent': values[7],
                        'nbr_count': values[8],
                        'tx_slot_count': values[9],
                        'parent_switch_count': values[10],
                        'rssi': values[11],
                        'route_count': values[12],
                        'delta_tx': values[13],
                        'delta_rx': values[14],
                        'app_packet_count': values[15],
                        # Labels: last 2 columns (16-17)
                        'is_attacker': values[16],
                        'attack_type': values[17]
                    }
                    data.append(features)
    
    print(f"Parsed {len(data)} records")
    return pd.DataFrame(data)

def detect_attack_row_based(df):
    """Detect attacks using ML - each row is a sample"""
    print("\n" + "="*60)
    print("ATTACK DETECTION - ROW-BASED APPROACH")
    print("="*60)
    
    # Feature columns (exclude labels, timestamp, node_id, parent_id, and the
    # synthetic run_id used only for multi-run group-aware CV).
    feature_cols = [col for col in df.columns
                    if col not in ['is_attacker', 'attack_type', 'timestamp',
                                    'node_id', 'parent_id', 'run_id']]
    
    X = df[feature_cols].values
    y = df['is_attacker'].values  # Binary classification: attacker or not
    
    print(f"\nFeatures used: {len(feature_cols)}")
    print(f"Features: {feature_cols}")
    print(f"\nDataset shape: {X.shape}")
    print(f"Attack samples: {np.sum(y == 1)}, Normal samples: {np.sum(y == 0)}")
    print(f"Attack percentage: {100 * np.sum(y == 1) / len(y):.2f}%")
    
    # Check if we have both classes
    if np.sum(y == 1) == 0:
        print("\nWARNING: No attack samples found in dataset!")
        return None, None, None, None
    
    if np.sum(y == 0) == 0:
        print("\nWARNING: No normal samples found in dataset!")
        return None, None, None, None
    
    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Split data
    print("\n" + "="*60)
    print("DATA SPLITTING")
    print("="*60)
    
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.3, random_state=42, stratify=y
        )
    except ValueError:
        # If stratification fails (e.g., too few samples of one class)
        print("Warning: Stratification failed, using random split")
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.3, random_state=42
        )
    
    print(f"Training set: {X_train.shape[0]} samples ({np.sum(y_train == 1)} attackers, {np.sum(y_train == 0)} normal)")
    print(f"Test set: {X_test.shape[0]} samples ({np.sum(y_test == 1)} attackers, {np.sum(y_test == 0)} normal)")
    
    # Test multiple models
    print("\n" + "="*60)
    print("MODEL TRAINING AND EVALUATION")
    print("="*60)
    
    models = {
        'Random Forest': RandomForestClassifier(
            n_estimators=100, max_depth=10, random_state=42, class_weight='balanced'
        ),
        'Gradient Boosting': GradientBoostingClassifier(
            n_estimators=100, max_depth=5, random_state=42
        ),
        'SVM (RBF)': SVC(
            kernel='rbf', probability=True, random_state=42, class_weight='balanced'
        ),
        'SVM (Linear)': SVC(
            kernel='linear', probability=True, random_state=42, class_weight='balanced'
        ),
        'Logistic Regression': LogisticRegression(
            max_iter=1000, random_state=42, class_weight='balanced'
        ),
        'K-Nearest Neighbors': KNeighborsClassifier(n_neighbors=5),
        'Naive Bayes': GaussianNB(),
        'Decision Tree': DecisionTreeClassifier(
            max_depth=10, random_state=42, class_weight='balanced'
        ),
        'AdaBoost': AdaBoostClassifier(
            n_estimators=50, random_state=42
        ),
    }
    if HAVE_XGB:
        models['XGBoost'] = XGBClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1,
            random_state=42, eval_metric='logloss',
            n_jobs=-1, verbosity=0,
        )
    if HAVE_LGBM:
        models['LightGBM'] = LGBMClassifier(
            n_estimators=200, max_depth=-1, learning_rate=0.1,
            random_state=42, class_weight='balanced',
            n_jobs=-1, verbose=-1,
        )
    
    # Cross Validation — both naive (row-level Stratified) and group-aware (per-node).
    # Naive split places different timestamps of the same node in train+test, which
    # leaks per-node behaviour and inflates F1. Group-aware split keeps each node in
    # exactly one fold so the model has to generalise to unseen nodes — this is the
    # number that matters for the dataset-difficulty target (CLAUDE.md macro-F1 <= 0.90).
    print("\n" + "="*60)
    print("CROSS VALIDATION (5-Fold; reports BOTH naive and group-aware)")
    print("="*60)

    cv_naive = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    groups = df['node_id'].values
    n_groups = len(np.unique(groups))
    # The attacker subset within each run carries the IDS-relevant signal.
    # If multiple runs were concatenated (run_id present), prefer per-(run, node)
    # groups so the same node from different runs is not split across folds.
    if 'run_id' in df.columns:
        groups = (df['run_id'].astype(str) + '|' + df['node_id'].astype(str)).values
        n_groups = len(np.unique(groups))
        print(f"Group-aware CV grouping by (run_id, node_id): {n_groups} unique groups.")
    else:
        print(f"Group-aware CV grouping by node_id: {n_groups} unique groups.")

    # Pick the most appropriate group-aware CV:
    #   - LOGO when the number of attacker groups is small (<= 30) — gives a
    #     stable per-attacker F1 distribution rather than a noisy 5-fold mean.
    #   - StratifiedGroupKFold(5) for larger group counts where LOGO would be
    #     too expensive.
    n_attacker_groups = len(np.unique(groups[y == 1])) if np.sum(y == 1) > 0 else 0
    use_group_cv = n_attacker_groups >= 2
    if use_group_cv and n_attacker_groups <= 30:
        cv_group = LeaveOneGroupOut()
        cv_group_name = f"LeaveOneGroupOut over {n_attacker_groups} attacker groups"
    elif use_group_cv:
        cv_group = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
        cv_group_name = f"StratifiedGroupKFold(5) over {n_groups} groups"
    else:
        cv_group = None
        cv_group_name = f"skipped ({n_attacker_groups} attacker groups)"
    print(f"Group-aware CV: {cv_group_name}.")
    scoring = {
        'accuracy': 'accuracy',
        'precision': make_scorer(precision_score, zero_division=0),
        'recall': make_scorer(recall_score, zero_division=0),
        'f1': make_scorer(f1_score, zero_division=0)
    }

    model_results = {}

    for model_name, model in models.items():
        try:
            print(f"\n{model_name}:")
            print("-" * 40)

            # Naive (row-level) CV
            cv_results = cross_validate(model, X_scaled, y, cv=cv_naive, scoring=scoring, return_train_score=True)
            
            cv_acc = cv_results['test_accuracy'].mean()
            cv_acc_std = cv_results['test_accuracy'].std()
            cv_prec = cv_results['test_precision'].mean()
            cv_prec_std = cv_results['test_precision'].std()
            cv_rec = cv_results['test_recall'].mean()
            cv_rec_std = cv_results['test_recall'].std()
            cv_f1 = cv_results['test_f1'].mean()
            cv_f1_std = cv_results['test_f1'].std()
            
            print(f"  Naive CV Accuracy:  {cv_acc:.4f} ± {cv_acc_std:.4f}")
            print(f"  Naive CV Precision: {cv_prec:.4f} ± {cv_prec_std:.4f}")
            print(f"  Naive CV Recall:    {cv_rec:.4f} ± {cv_rec_std:.4f}")
            print(f"  Naive CV F1-Score:  {cv_f1:.4f} ± {cv_f1_std:.4f}")

            # Group-aware CV — the metric that matters for IDS generalisation.
            # We need to distinguish two zero-F1 cases:
            #   (a) test fold had no attackers at all -> F1 truly undefined,
            #       exclude from the mean (uninformative).
            #   (b) test fold had attackers but the model failed to detect any
            #       -> F1 = 0 is a real result, INCLUDE in the mean.
            # The previous heuristic "(rec + prec) > 0" wrongly conflated
            # (a) and (b); excluding (b) inflated the reported F1. The fix
            # is to pre-compute, per fold, whether the test set has any
            # positives, and include the fold iff that's true.
            if use_group_cv:
                group_results = cross_validate(model, X_scaled, y, groups=groups,
                                                cv=cv_group, scoring=scoring,
                                                return_train_score=False)
                f1_arr = np.asarray(group_results['test_f1'])
                rec_arr = np.asarray(group_results['test_recall'])
                prec_arr = np.asarray(group_results['test_precision'])
                acc_arr = np.asarray(group_results['test_accuracy'])

                # Recompute the same fold sequence to know which test
                # indices each fold uses (cross_validate doesn't return
                # them directly), then check whether any positives are
                # in that test set.
                attacker_fold_mask = np.zeros(len(f1_arr), dtype=bool)
                for fold_i, (_, test_idx) in enumerate(cv_group.split(X_scaled, y, groups=groups)):
                    if np.any(y[test_idx] == 1):
                        attacker_fold_mask[fold_i] = True
                n_attacker_folds = int(attacker_fold_mask.sum())
                n_total_folds = len(f1_arr)

                if n_attacker_folds > 0:
                    f1_attacker = f1_arr[attacker_fold_mask]
                    gcv_f1 = f1_attacker.mean()
                    gcv_f1_std = f1_attacker.std()
                    # 95% CI via normal approx (use sample std / sqrt(n) * 1.96)
                    if n_attacker_folds > 1:
                        ci95 = 1.96 * gcv_f1_std / np.sqrt(n_attacker_folds)
                    else:
                        ci95 = float('nan')
                else:
                    gcv_f1 = gcv_f1_std = ci95 = float('nan')
                gcv_acc = acc_arr.mean()
                gcv_acc_std = acc_arr.std()
                gcv_prec = prec_arr[attacker_fold_mask].mean() if n_attacker_folds else float('nan')
                gcv_prec_std = prec_arr[attacker_fold_mask].std() if n_attacker_folds > 1 else float('nan')
                gcv_rec = rec_arr[attacker_fold_mask].mean() if n_attacker_folds else float('nan')
                gcv_rec_std = rec_arr[attacker_fold_mask].std() if n_attacker_folds > 1 else float('nan')

                print(f"  Group CV Accuracy:  {gcv_acc:.4f} ± {gcv_acc_std:.4f}  (all {n_total_folds} folds)")
                print(f"  Group CV F1-Score:  {gcv_f1:.4f} ± {gcv_f1_std:.4f}  (n={n_attacker_folds} attacker-bearing folds; 95% CI ±{ci95:.4f})")
                print(f"  Group CV Precision: {gcv_prec:.4f} ± {gcv_prec_std:.4f}")
                print(f"  Group CV Recall:    {gcv_rec:.4f} ± {gcv_rec_std:.4f}")
            else:
                gcv_acc = gcv_acc_std = gcv_prec = gcv_prec_std = float('nan')
                gcv_rec = gcv_rec_std = gcv_f1 = gcv_f1_std = ci95 = float('nan')
                n_attacker_folds = 0
                n_total_folds = 0

            # Train on training set and evaluate on test set
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
            y_pred_proba = model.predict_proba(X_test)[:, 1] if model.predict_proba(X_test).shape[1] == 2 else model.predict_proba(X_test)[:, 0]
            
            test_acc = accuracy_score(y_test, y_pred)
            test_prec = precision_score(y_test, y_pred, zero_division=0)
            test_rec = recall_score(y_test, y_pred, zero_division=0)
            test_f1 = f1_score(y_test, y_pred, zero_division=0)
            
            print(f"  Test Accuracy:  {test_acc:.4f}")
            print(f"  Test Precision: {test_prec:.4f}")
            print(f"  Test Recall:    {test_rec:.4f}")
            print(f"  Test F1-Score:  {test_f1:.4f}")
            
            model_results[model_name] = {
                'cv_accuracy': cv_acc,
                'cv_accuracy_std': cv_acc_std,
                'cv_precision': cv_prec,
                'cv_precision_std': cv_prec_std,
                'cv_recall': cv_rec,
                'cv_recall_std': cv_rec_std,
                'cv_f1': cv_f1,
                'cv_f1_std': cv_f1_std,
                'group_cv_accuracy': gcv_acc,
                'group_cv_accuracy_std': gcv_acc_std,
                'group_cv_precision': gcv_prec,
                'group_cv_precision_std': gcv_prec_std,
                'group_cv_recall': gcv_rec,
                'group_cv_recall_std': gcv_rec_std,
                'group_cv_f1': gcv_f1,
                'group_cv_f1_std': gcv_f1_std,
                'group_cv_f1_ci95': ci95,
                'group_cv_n_attacker_folds': n_attacker_folds,
                'group_cv_n_total_folds': n_total_folds,
                'test_accuracy': test_acc,
                'test_precision': test_prec,
                'test_recall': test_rec,
                'test_f1': test_f1,
                'model': model,
                'y_pred': y_pred,
                'y_test': y_test,
                'y_pred_proba': y_pred_proba
            }
            
        except Exception as e:
            print(f"  ERROR: {model_name} failed - {str(e)}")
            continue
    
    if len(model_results) == 0:
        print("\nWARNING: No models successfully trained!")
        return None, None, None, None
    
    # Print comparison table — naive vs group-aware F1 with 95% CI on the
    # group-aware F1. The CI is computed only over folds where the test set
    # had at least one attacker (others are uninformative for per-attacker
    # generalisation). The "Folds" column shows how many of the total CV
    # folds that was — small n means the CI is wide.
    print("\n" + "="*108)
    print("MODEL COMPARISON SUMMARY (naive CV vs group-aware CV with 95% CI)")
    print("="*108)
    print(f"{'Model':<22} {'NaiveF1':>10} {'GroupF1':>16} {'95%CI':>10} {'Folds':>10} {'NaiveAcc':>10} {'GroupAcc':>10} {'TestAcc':>10}")
    print("-"*108)

    def _sort_key(item):
        results = item[1]
        gcv = results.get('group_cv_f1')
        if gcv is None or (isinstance(gcv, float) and np.isnan(gcv)):
            return results['test_accuracy']
        return gcv
    sorted_models = sorted(model_results.items(), key=_sort_key, reverse=True)

    for model_name, results in sorted_models:
        gcv_f1 = results.get('group_cv_f1', float('nan'))
        gcv_f1_std = results.get('group_cv_f1_std', float('nan'))
        gcv_ci = results.get('group_cv_f1_ci95', float('nan'))
        gcv_acc = results.get('group_cv_accuracy', float('nan'))
        n_attacker_folds = results.get('group_cv_n_attacker_folds', 0)
        n_total_folds = results.get('group_cv_n_total_folds', 0)
        gcv_str = f"{gcv_f1:.4f}±{gcv_f1_std:.3f}" if not np.isnan(gcv_f1) else "      n/a       "
        ci_str  = f"±{gcv_ci:.4f}" if not np.isnan(gcv_ci) else "    n/a"
        folds_str = f"{n_attacker_folds}/{n_total_folds}"
        gacc_str = f"{gcv_acc:.4f}" if not np.isnan(gcv_acc) else "  n/a "
        print(f"{model_name:<22} "
              f"{results['cv_f1']:>6.4f}±{results['cv_f1_std']:.3f} "
              f"{gcv_str:>16} "
              f"{ci_str:>10} "
              f"{folds_str:>10} "
              f"{results['cv_accuracy']:>10.4f} "
              f"{gacc_str:>10} "
              f"{results['test_accuracy']:>10.4f}")
    
    # Best model
    best_model_name = sorted_models[0][0]
    best_model = sorted_models[0][1]['model']
    best_results = sorted_models[0][1]
    
    print(f"\n{'='*80}")
    print(f"BEST MODEL: {best_model_name}")
    print(f"{'='*80}")
    print(f"Cross-Validation Performance:")
    print(f"  Accuracy:  {best_results['cv_accuracy']:.4f} ± {best_results['cv_accuracy_std']:.4f}")
    print(f"  Precision: {best_results['cv_precision']:.4f} ± {best_results['cv_precision_std']:.4f}")
    print(f"  Recall:    {best_results['cv_recall']:.4f} ± {best_results['cv_recall_std']:.4f}")
    print(f"  F1-Score:  {best_results['cv_f1']:.4f} ± {best_results['cv_f1_std']:.4f}")
    print(f"\nTest Set Performance:")
    print(f"  Accuracy:  {best_results['test_accuracy']:.4f}")
    print(f"  Precision: {best_results['test_precision']:.4f}")
    print(f"  Recall:    {best_results['test_recall']:.4f}")
    print(f"  F1-Score:  {best_results['test_f1']:.4f}")
    print(f"{'='*80}")
    
    # Detailed classification report for best model
    print("\n" + "="*60)
    print(f"DETAILED CLASSIFICATION REPORT - {best_model_name}")
    print("="*60)
    print("\nConfusion Matrix:")
    print(confusion_matrix(best_results['y_test'], best_results['y_pred']))
    print("\nClassification Report:")
    print(classification_report(best_results['y_test'], best_results['y_pred'], 
                              target_names=['Normal', 'Attacker']))
    
    # Feature importance (if available)
    if hasattr(best_model, 'feature_importances_'):
        print("\n" + "="*60)
        print("TOP 10 MOST IMPORTANT FEATURES")
        print("="*60)
        feature_importance = pd.DataFrame({
            'feature': feature_cols,
            'importance': best_model.feature_importances_
        }).sort_values('importance', ascending=False)
        print(feature_importance.head(10).to_string(index=False))
    
    # Predictions on full dataset
    print("\n" + "="*60)
    print("FULL DATASET PREDICTIONS")
    print("="*60)
    
    best_model.fit(X_scaled, y)  # Retrain on full dataset
    y_pred_full = best_model.predict(X_scaled)
    y_pred_proba_full = best_model.predict_proba(X_scaled)[:, 1] if best_model.predict_proba(X_scaled).shape[1] == 2 else best_model.predict_proba(X_scaled)[:, 0]
    
    df['predicted_attacker'] = y_pred_full
    df['attack_probability'] = y_pred_proba_full
    
    # Calculate overall accuracy
    overall_accuracy = accuracy_score(y, y_pred_full)
    overall_precision = precision_score(y, y_pred_full, zero_division=0)
    overall_recall = recall_score(y, y_pred_full, zero_division=0)
    overall_f1 = f1_score(y, y_pred_full, zero_division=0)
    
    print(f"\nFull Dataset Performance:")
    print(f"  Accuracy:  {overall_accuracy:.4f} ({overall_accuracy*100:.2f}%)")
    print(f"  Precision: {overall_precision:.4f} ({overall_precision*100:.2f}%)")
    print(f"  Recall:    {overall_recall:.4f} ({overall_recall*100:.2f}%)")
    print(f"  F1-Score:  {overall_f1:.4f} ({overall_f1*100:.2f}%)")
    
    # Show prediction statistics by node
    print("\n" + "="*60)
    print("PREDICTION STATISTICS BY NODE")
    print("="*60)
    
    node_stats = []
    for node_id in sorted(df['node_id'].unique()):
        node_df = df[df['node_id'] == node_id]
        actual_attacks = np.sum(node_df['is_attacker'] == 1)
        predicted_attacks = np.sum(node_df['predicted_attacker'] == 1)
        total_samples = len(node_df)
        
        # Calculate accuracy for this node
        node_accuracy = accuracy_score(node_df['is_attacker'], node_df['predicted_attacker'])
        
        node_stats.append({
            'node_id': node_id,
            'total_samples': total_samples,
            'actual_attack_samples': actual_attacks,
            'predicted_attack_samples': predicted_attacks,
            'node_accuracy': node_accuracy,
            'actual_is_attacker': 1 if actual_attacks > 0 else 0,
            'predicted_is_attacker': 1 if predicted_attacks > total_samples * 0.5 else 0  # Majority vote
        })
    
    node_stats_df = pd.DataFrame(node_stats)
    print(node_stats_df.to_string(index=False))
    
    # Show nodes where predictions differ from actual
    print("\n" + "="*60)
    print("NODES WITH PREDICTION DISCREPANCIES")
    print("="*60)
    discrepancies = node_stats_df[node_stats_df['actual_is_attacker'] != node_stats_df['predicted_is_attacker']]
    if len(discrepancies) > 0:
        print(discrepancies.to_string(index=False))
    else:
        print("No discrepancies found - all nodes correctly classified!")
    
    return df, best_model, scaler, feature_cols

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 attack_detection_row_based_ml.py <log_file> [<log_file2> ...]")
        sys.exit(1)

    log_files = sys.argv[1:]

    # When multiple logs are passed (multi-run randomised dataset), each
    # file is a separate sim run. We tag each row with run_id = filename
    # stem so the group-aware CV groups by (run_id, node_id) and treats
    # the same node from different runs as different attacker observations.
    dfs = []
    for log_file in log_files:
        df = parse_log_file(log_file)
        if len(df) == 0:
            print(f"WARNING: no data in {log_file}; skipping")
            continue
        if len(log_files) > 1:
            run_id = log_file
            for suffix in ('.log', '_row_based_ml_results.csv'):
                if run_id.endswith(suffix):
                    run_id = run_id[:-len(suffix)]
            df['run_id'] = run_id
        dfs.append(df)

    if not dfs:
        print("No data found in any log file!")
        sys.exit(1)

    df = pd.concat(dfs, ignore_index=True) if len(dfs) > 1 else dfs[0]
    print(f"\nLoaded {len(df)} total rows across {len(dfs)} log file(s).")
    log_file = log_files[0]  # used below only for the output filename

    if len(df) == 0:
        print("No data found in log file!")
        sys.exit(1)
    
    # Detect attacks
    df_results, model, scaler, features = detect_attack_row_based(df)
    
    if df_results is not None:
        # Save results
        output_file = log_file.replace('.log', '_row_based_ml_results.csv')
        df_results.to_csv(output_file, index=False)
        print(f"\nResults saved to: {output_file}")
        
        print("\n" + "="*60)
        print("ANALYSIS COMPLETE")
        print("="*60)
        print(f"\nSuccessfully detected attacks with row-based ML approach!")
        print(f"Total samples analyzed: {len(df_results)}")
        print(f"Attack samples: {np.sum(df_results['is_attacker'] == 1)}")
        print(f"Normal samples: {np.sum(df_results['is_attacker'] == 0)}")
    else:
        print("\nAnalysis failed!")

if __name__ == "__main__":
    main()

