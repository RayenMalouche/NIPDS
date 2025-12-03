# train_models_real_dataset.py - Train with NF-UNSW-NB15-v3 (NetFlow_v3 Features)

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_auc_score
import pickle
import os
from datetime import datetime


class NetFlowV3DatasetLoader:
    """Load and preprocess NF-UNSW-NB15-v3 dataset (NetFlow Metasploit v3 features)"""

    def __init__(self):
        self.feature_names = []
        self.scaler = StandardScaler()

    def load_nf_unsw_nb15_v3(self, csv_path):

        print(f"[+] Loading NF-UNSW-NB15-v3 dataset from:\n    {csv_path}")

        try:
            # The actual data file has headers, so we read normally
            df = pd.read_csv(csv_path, low_memory=False)
            print(f"[+] Loaded {len(df)} samples")

            # Show label distribution (the dataset uses 'Label' column: 0 = Benign, 1 = Attack)
            if 'Label' in df.columns:
                print("\n[+] Label distribution:")
                print(df['Label'].value_counts())

            # Show attack categories if present
            if 'Attack' in df.columns:
                print("\n[+] Attack category distribution:")
                print(df['Attack'].value_counts())

            return df

        except Exception as e:
            print(f"[!] Error loading dataset: {e}")
            return None

    def preprocess_nf_unsw_nb15_v3(self, df):
        """Preprocess NF-UNSW-NB15-v3 dataset"""
        print("\n[+] Preprocessing NF-UNSW-NB15-v3 dataset...")

        # Drop IP addresses (causes overfitting and leakage)
        df = df.drop(['IPV4_SRC_ADDR', 'IPV4_DST_ADDR'], axis=1, errors='ignore')

        # Optional: drop timestamp columns if they exist
        timestamp_cols = ['FLOW_START_MILLISECONDS', 'FLOW_END_MILLISECONDS']
        df = df.drop(timestamp_cols, axis=1, errors='ignore')
        # Target label
        if 'Label' not in df.columns:
            raise ValueError("Column 'Label' not found! Check your dataset.")

        y = df['Label'].astype(int)
        X = df.drop(['Label'], axis=1)

        # Optional: also drop 'Attack' (attack subcategory) if you only want binary classification
        if 'Attack' in X.columns:
            print("[+] Dropping 'Attack' column (keeping only binary Label)")
            X = X.drop('Attack', axis=1)

        # Handle categorical features (only L7_PROTO might be categorical here, others are numeric)
        if 'L7_PROTO' in X.columns:
            X['L7_PROTO'] = X['L7_PROTO'].astype(float).fillna(0)

        if 'PROTOCOL' in X.columns:
            X['PROTOCOL'] = X['PROTOCOL'].astype(float)

        # Convert everything to numeric
        for col in X.columns:
            X[col] = pd.to_numeric(X[col], errors='coerce')

        # Fill NaN / Inf
        X = X.fillna(0)
        X = X.replace([np.inf, -np.inf], 0)

        self.feature_names = X.columns.tolist()

        print(f"[+] Final feature count: {len(self.feature_names)}")
        print(f"[+] Benign samples : {len(y[y == 0]):,}")
        print(f"[+] Attack samples : {len(y[y == 1]):,}")

        return X, y


class RealDatasetTrainer:
    """Train models on real datasets"""

    def __init__(self, X, y):
        self.X = X
        self.y = y
        self.models = {}
        self.scaler = StandardScaler()
        self.results = {}

    def prepare_data(self, test_size=0.2):
        print(f"\n[+] Splitting data (test_size={test_size})...")
        X_train, X_test, y_train, y_test = train_test_split(
            self.X, self.y, test_size=test_size, random_state=42, stratify=self.y
        )

        print(f"[+] Training samples: {len(X_train):,}")
        print(f"[+] Testing samples : {len(X_test):,}")

        print("[+] Scaling features with StandardScaler...")
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        return X_train_scaled, X_test_scaled, y_train, y_test

    def train_all_models(self):
        print("\n[+] Starting training of multiple models...")

        X_train, X_test, y_train, y_test = self.prepare_data()

        models = {
            'RandomForest': RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1,
                verbose=1
            ),
            'GradientBoosting': GradientBoostingClassifier(
                n_estimators=200,
                learning_rate=0.1,
                max_depth=6,
                subsample=0.8,
                random_state=42,
                verbose=1
            )
        }

        for name, model in models.items():
            print(f"\n{'=' * 70}")
            print(f"Training {name}...")
            print('=' * 70)

            model.fit(X_train, y_train)

            y_pred = model.predict(X_test)
            y_proba = model.predict_proba(X_test)[:, 1]

            accuracy = model.score(X_test, y_test)
            auc = roc_auc_score(y_test, y_proba)

            print(f"\nAccuracy : {accuracy:.5f}")
            print(f"ROC-AUC  : {auc:.5f}")
            print("\nClassification Report:")
            print(classification_report(y_test, y_pred, target_names=['Benign', 'Attack']))

            self.models[name] = model
            self.results[name] = {'accuracy': accuracy, 'auc': auc}

        return self.models, self.results

    def save_best_model(self, feature_names, output_dir='models'):
        os.makedirs(output_dir, exist_ok=True)

        best_name = max(self.results, key=lambda k: self.results[k]['auc'])
        best_model = self.models[best_name]

        print(f"\n[+] Best model by AUC: {best_name}")
        print(f"    Accuracy: {self.results[best_name]['accuracy']:.5f}")
        print(f"    AUC     : {self.results[best_name]['auc']:.5f}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_path = os.path.join(output_dir, f"nids_nf_unsw_nb15_v3_{best_name.lower()}_{timestamp}.pkl")

        save_data = {
            'model': best_model,
            'scaler': self.scaler,
            'feature_names': feature_names,
            'model_name': best_name,
            'metrics': self.results[best_name],
            'trained_on': timestamp,
            'dataset': 'NF-UNSW-NB15-v3'
        }

        with open(model_path, 'wb') as f:
            pickle.dump(save_data, f)

        print(f"[+] Model saved successfully → {model_path}")
        return model_path


def main():
    print("=" * 80)
    print("NIDS Training on NF-UNSW-NB15-v3 (NetFlow v3 Features)")
    print("=" * 80)

    # Default path (you can change it or keep input prompt)
    default_path = r"C:\Users\rayen\Desktop\coding\Python\nids-system\datasets\NF-UNSW-NB15-v3\NF-UNSW-NB15-v3.csv"

    print(f"\nDefault dataset path:\n{default_path}")
    use_default = input("\nUse default path? (y/n): ").strip().lower()

    if use_default == 'y' or use_default == '':
        csv_path = default_path
    else:
        csv_path = input("Enter full path to NF-UNSW-NB15-v3.csv: ").strip(' "\'')

    if not os.path.exists(csv_path):
        print("[!] File not found! Please check the path.")
        return

    # Load and preprocess
    loader = NetFlowV3DatasetLoader()
    df = loader.load_nf_unsw_nb15_v3(csv_path)

    if df is None:
        return

    X, y = loader.preprocess_nf_unsw_nb15_v3(df)

    # Train
    trainer = RealDatasetTrainer(X, y)
    models, results = trainer.train_all_models()

    # Save best model
    model_path = trainer.save_best_model(loader.feature_names)

    print("\n" + "=" * 80)
    print("Training completed successfully!")
    print(f"Best model saved: {model_path}")
    print("=" * 80)


if __name__ == "__main__":
    main()