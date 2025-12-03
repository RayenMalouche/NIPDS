# train_models.py - Dataset Generation and Model Training

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import matplotlib.pyplot as plt
import seaborn as sns
import pickle
import os
from datetime import datetime


class SyntheticDatasetGenerator:
    """Generate synthetic network traffic dataset for training"""

    def __init__(self, n_samples=10000):
        self.n_samples = n_samples

    def generate_normal_traffic(self, n):
        """Generate normal network traffic patterns"""
        data = {
            'packet_count': np.random.poisson(50, n),
            'avg_packet_size': np.random.normal(800, 200, n).clip(64, 1500),
            'std_packet_size': np.random.normal(100, 30, n).clip(0),
            'max_packet_size': np.random.normal(1400, 100, n).clip(500, 1500),
            'tcp_ratio': np.random.beta(8, 2, n),
            'udp_ratio': np.random.beta(2, 8, n),
            'unique_dst_ports': np.random.randint(1, 10, n),
            'unique_src_ports': np.random.randint(1, 5, n),
            'avg_ttl': np.random.normal(64, 10, n).clip(30, 128),
            'syn_count': np.random.poisson(5, n),
            'packet_rate': np.random.gamma(2, 10, n),
            'label': 0  # Normal traffic
        }
        return pd.DataFrame(data)

    def generate_port_scan_traffic(self, n):
        """Generate port scanning attack patterns"""
        data = {
            'packet_count': np.random.poisson(100, n),
            'avg_packet_size': np.random.normal(64, 10, n).clip(40, 100),
            'std_packet_size': np.random.normal(20, 5, n).clip(0),
            'max_packet_size': np.random.normal(100, 20, n).clip(60, 150),
            'tcp_ratio': np.random.beta(9, 1, n),
            'udp_ratio': np.random.beta(1, 9, n),
            'unique_dst_ports': np.random.randint(50, 500, n),  # Many ports
            'unique_src_ports': np.random.randint(1, 3, n),
            'avg_ttl': np.random.normal(64, 5, n).clip(50, 80),
            'syn_count': np.random.poisson(80, n),
            'packet_rate': np.random.gamma(5, 20, n),
            'label': 1  # Port scan
        }
        return pd.DataFrame(data)

    def generate_ddos_traffic(self, n):
        """Generate DDoS attack patterns"""
        data = {
            'packet_count': np.random.poisson(500, n),
            'avg_packet_size': np.random.normal(64, 20, n).clip(40, 200),
            'std_packet_size': np.random.normal(10, 3, n).clip(0),
            'max_packet_size': np.random.normal(200, 50, n).clip(100, 500),
            'tcp_ratio': np.random.beta(7, 3, n),
            'udp_ratio': np.random.beta(3, 7, n),
            'unique_dst_ports': np.random.randint(1, 5, n),
            'unique_src_ports': np.random.randint(100, 1000, n),
            'avg_ttl': np.random.normal(64, 20, n).clip(20, 100),
            'syn_count': np.random.poisson(400, n),
            'packet_rate': np.random.gamma(10, 100, n),  # Very high rate
            'label': 1  # DDoS
        }
        return pd.DataFrame(data)

    def generate_brute_force_traffic(self, n):
        """Generate brute force attack patterns"""
        data = {
            'packet_count': np.random.poisson(200, n),
            'avg_packet_size': np.random.normal(400, 100, n).clip(200, 800),
            'std_packet_size': np.random.normal(50, 10, n).clip(0),
            'max_packet_size': np.random.normal(800, 100, n).clip(500, 1200),
            'tcp_ratio': np.random.beta(9, 1, n),
            'udp_ratio': np.random.beta(1, 9, n),
            'unique_dst_ports': np.random.randint(1, 3, n),  # Usually SSH, RDP
            'unique_src_ports': np.random.randint(50, 200, n),
            'avg_ttl': np.random.normal(64, 8, n).clip(40, 90),
            'syn_count': np.random.poisson(150, n),
            'packet_rate': np.random.gamma(4, 15, n),
            'label': 1  # Brute force
        }
        return pd.DataFrame(data)

    def generate_sql_injection_traffic(self, n):
        """Generate SQL injection attack patterns"""
        data = {
            'packet_count': np.random.poisson(30, n),
            'avg_packet_size': np.random.normal(1200, 200, n).clip(800, 1500),
            'std_packet_size': np.random.normal(150, 30, n).clip(0),
            'max_packet_size': np.random.normal(1500, 100, n).clip(1200, 1500),
            'tcp_ratio': np.random.beta(9, 1, n),
            'udp_ratio': np.random.beta(1, 9, n),
            'unique_dst_ports': np.random.randint(1, 3, n),
            'unique_src_ports': np.random.randint(1, 5, n),
            'avg_ttl': np.random.normal(64, 8, n).clip(40, 90),
            'syn_count': np.random.poisson(20, n),
            'packet_rate': np.random.gamma(2, 5, n),
            'label': 1  # SQL injection
        }
        return pd.DataFrame(data)

    def generate_full_dataset(self):
        """Generate complete balanced dataset"""
        print("[+] Generating synthetic dataset...")

        # Calculate samples per class
        samples_per_class = self.n_samples // 5

        # Generate each traffic type
        normal = self.generate_normal_traffic(samples_per_class * 2)  # More normal traffic
        port_scan = self.generate_port_scan_traffic(samples_per_class)
        ddos = self.generate_ddos_traffic(samples_per_class)
        brute_force = self.generate_brute_force_traffic(samples_per_class // 2)
        sql_injection = self.generate_sql_injection_traffic(samples_per_class // 2)

        # Combine all data
        dataset = pd.concat([
            normal, port_scan, ddos, brute_force, sql_injection
        ], ignore_index=True)

        # Shuffle dataset
        dataset = dataset.sample(frac=1, random_state=42).reset_index(drop=True)

        print(f"[+] Generated {len(dataset)} samples")
        print(f"    Normal: {(dataset['label'] == 0).sum()}")
        print(f"    Malicious: {(dataset['label'] == 1).sum()}")

        return dataset


class ModelTrainer:
    """Train and evaluate multiple ML models"""

    def __init__(self, dataset):
        self.dataset = dataset
        self.models = {}
        self.scaler = StandardScaler()
        self.results = {}

    def prepare_data(self, test_size=0.2):
        """Split and scale dataset"""
        X = self.dataset.drop('label', axis=1)
        y = self.dataset['label']

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )

        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        return X_train_scaled, X_test_scaled, y_train, y_test

    def train_all_models(self):
        """Train multiple models and compare performance"""
        print("\n[+] Training models...")

        X_train, X_test, y_train, y_test = self.prepare_data()

        # Define models
        models = {
            'Random Forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=15,
                min_samples_split=5,
                random_state=42,
                n_jobs=-1
            ),
            'Gradient Boosting': GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=5,
                random_state=42
            ),
            'Neural Network': MLPClassifier(
                hidden_layer_sizes=(100, 50, 25),
                activation='relu',
                solver='adam',
                max_iter=500,
                random_state=42
            )
        }

        # Train and evaluate each model
        for name, model in models.items():
            print(f"\n{'=' * 50}")
            print(f"Training {name}...")

            # Train model
            model.fit(X_train, y_train)

            # Make predictions
            y_pred = model.predict(X_test)
            y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None

            # Calculate metrics
            accuracy = model.score(X_test, y_test)

            print(f"\nAccuracy: {accuracy:.4f}")
            print("\nClassification Report:")
            print(classification_report(y_test, y_pred, target_names=['Normal', 'Malicious']))

            if y_proba is not None:
                auc = roc_auc_score(y_test, y_proba)
                print(f"ROC-AUC Score: {auc:.4f}")
                self.results[name] = {'accuracy': accuracy, 'auc': auc}
            else:
                self.results[name] = {'accuracy': accuracy}

            # Cross-validation
            cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='accuracy')
            print(f"Cross-validation scores: {cv_scores}")
            print(f"Mean CV Score: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")

            self.models[name] = model

        return self.models, self.results

    def save_best_model(self, output_dir='models'):
        """Save the best performing model"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Find best model based on accuracy
        best_model_name = max(self.results, key=lambda x: self.results[x]['accuracy'])
        best_model = self.models[best_model_name]

        print(f"\n[+] Best model: {best_model_name}")
        print(f"    Accuracy: {self.results[best_model_name]['accuracy']:.4f}")

        # Save model and scaler
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_path = os.path.join(output_dir, f'nids_model_{timestamp}.pkl')

        model_data = {
            'model': best_model,
            'scaler': self.scaler,
            'feature_names': list(self.dataset.columns[:-1]),
            'model_name': best_model_name,
            'metrics': self.results[best_model_name],
            'trained_on': timestamp
        }

        with open(model_path, 'wb') as f:
            pickle.dump(model_data, f)

        print(f"[+] Model saved to {model_path}")

        return model_path

    def plot_confusion_matrix(self, model_name='Random Forest'):
        """Plot confusion matrix for a specific model"""
        X_train, X_test, y_train, y_test = self.prepare_data()
        model = self.models[model_name]
        y_pred = model.predict(X_test)

        cm = confusion_matrix(y_test, y_pred)

        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                    xticklabels=['Normal', 'Malicious'],
                    yticklabels=['Normal', 'Malicious'])
        plt.title(f'Confusion Matrix - {model_name}')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.tight_layout()
        plt.savefig(f'confusion_matrix_{model_name.replace(" ", "_").lower()}.png')
        print(f"[+] Confusion matrix saved")


def main():
    """Main training pipeline"""
    print("=" * 60)
    print("NIDS Model Training Pipeline")
    print("=" * 60)

    # Generate dataset
    generator = SyntheticDatasetGenerator(n_samples=10000)
    dataset = generator.generate_full_dataset()

    # Save dataset
    dataset.to_csv('datasets/nids_training_data.csv', index=False)
    print("[+] Dataset saved to datasets/nids_training_data.csv")

    # Train models
    trainer = ModelTrainer(dataset)
    models, results = trainer.train_all_models()

    # Save best model
    model_path = trainer.save_best_model()

    # Plot confusion matrix
    trainer.plot_confusion_matrix('Random Forest')

    print("\n[+] Training complete!")
    print(f"[+] Best model saved to: {model_path}")

    return models, results


if __name__ == "__main__":
    main()