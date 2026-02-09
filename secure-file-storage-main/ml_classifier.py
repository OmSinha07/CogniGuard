
# ============================================
# FILE 2: ml_classifier.py (NEW)
# ============================================

import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib
import os
import math

class FileSecurityClassifier:
    """ML-based file sensitivity classifier"""
    
    def __init__(self, model_path='ml_model.pkl'):
        self.model_path = model_path
        self.model = None
        self.label_encoder = LabelEncoder()
        
        # Extension to category mapping
        self.extension_categories = {
            # Low sensitivity
            'txt': 0, 'jpg': 0, 'jpeg': 0, 'png': 0, 'gif': 0, 'bmp': 0,
            'mp3': 0, 'mp4': 0, 'wav': 0, 'avi': 0,
            
            # Medium sensitivity  
            'pdf': 1, 'doc': 1, 'docx': 1, 'xls': 1, 'xlsx': 1, 
            'ppt': 1, 'pptx': 1, 'zip': 1, 'rar': 1,
            
            # High sensitivity
            'db': 2, 'sql': 2, 'key': 2, 'pem': 2, 'p12': 2,
            'pfx': 2, 'cer': 2, 'crt': 2
        }
        
        # Load or create model
        if os.path.exists(model_path):
            self.load_model()
        else:
            self.train_initial_model()
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of file content"""
        if len(data) == 0:
            return 0
        
        # Sample data if too large (first 10KB)
        sample = data[:10240] if len(data) > 10240 else data
        
        # Count byte frequencies
        byte_counts = np.bincount(np.frombuffer(sample, dtype=np.uint8), minlength=256)
        probabilities = byte_counts[byte_counts > 0] / len(sample)
        
        # Calculate entropy
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return entropy
    
    def extract_features(self, file_data, filename):
        """Extract features from file for ML classification"""
        file_size = len(file_data)
        extension = filename.split('.')[-1].lower() if '.' in filename else ''
        
        # Calculate entropy
        entropy = self.calculate_entropy(file_data)
        
        # Extension category
        ext_category = self.extension_categories.get(extension, 1)  # Default medium
        
        # Size categories (in KB)
        size_kb = file_size / 1024
        
        features = {
            'file_size': file_size,
            'size_kb': size_kb,
            'extension_category': ext_category,
            'entropy': entropy,
            'is_large': 1 if file_size > 10 * 1024 * 1024 else 0,  # >10MB
            'is_small': 1 if file_size < 100 * 1024 else 0,  # <100KB
        }
        
        return features
    
    def train_initial_model(self):
        """Train initial model with synthetic data"""
        print("🧠 Training initial ML model...")
        
        # Generate synthetic training data
        np.random.seed(42)
        n_samples = 300
        
        data = []
        
        # LOW sensitivity samples (100)
        for i in range(100):
            data.append({
                'file_size': np.random.randint(1000, 100000),  # 1KB - 100KB
                'size_kb': np.random.uniform(1, 100),
                'extension_category': 0,  # Low category
                'entropy': np.random.uniform(3.0, 5.0),  # Low entropy
                'is_large': 0,
                'is_small': 1,
                'sensitivity': 'LOW'
            })
        
        # MEDIUM sensitivity samples (100)
        for i in range(100):
            data.append({
                'file_size': np.random.randint(100000, 10000000),  # 100KB - 10MB
                'size_kb': np.random.uniform(100, 10000),
                'extension_category': 1,  # Medium category
                'entropy': np.random.uniform(5.0, 6.5),  # Medium entropy
                'is_large': 0,
                'is_small': 0,
                'sensitivity': 'MEDIUM'
            })
        
        # HIGH sensitivity samples (100)
        for i in range(100):
            data.append({
                'file_size': np.random.randint(10000000, 100000000),  # 10MB - 100MB
                'size_kb': np.random.uniform(10000, 100000),
                'extension_category': 2,  # High category
                'entropy': np.random.uniform(6.5, 8.0),  # High entropy
                'is_large': 1,
                'is_small': 0,
                'sensitivity': 'HIGH'
            })
        
        # Create DataFrame
        df = pd.DataFrame(data)
        
        # Prepare features and labels
        X = df[['file_size', 'size_kb', 'extension_category', 'entropy', 'is_large', 'is_small']]
        y = df['sensitivity']
        
        # Train Random Forest classifier
        self.model = RandomForestClassifier(
            n_estimators=50,
            max_depth=10,
            random_state=42
        )
        self.model.fit(X, y)
        
        # Save model
        self.save_model()
        
        print("✅ Initial ML model trained and saved!")
        
        # Print feature importances
        feature_names = ['file_size', 'size_kb', 'ext_category', 'entropy', 'is_large', 'is_small']
        importances = self.model.feature_importances_
        print("\n📊 Feature Importances:")
        for name, importance in zip(feature_names, importances):
            print(f"  {name}: {importance:.3f}")
    
    def predict_sensitivity(self, file_data, filename):
        """Predict file sensitivity level"""
        # Extract features
        features = self.extract_features(file_data, filename)
        
        # Prepare feature vector
        X = np.array([[
            features['file_size'],
            features['size_kb'],
            features['extension_category'],
            features['entropy'],
            features['is_large'],
            features['is_small']
        ]])
        
        # Predict
        sensitivity = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        
        # Get confidence
        confidence = max(probabilities)
        
        # Map probabilities to classes (sorted alphabetically: HIGH, LOW, MEDIUM)
        classes = self.model.classes_
        prob_dict = {cls: prob for cls, prob in zip(classes, probabilities)}
        
        result = {
            'sensitivity': sensitivity,
            'confidence': confidence,
            'features': features,
            'probabilities': prob_dict
        }
        
        return result
    
    def save_model(self):
        """Save trained model to disk"""
        joblib.dump(self.model, self.model_path)
    
    def load_model(self):
        """Load trained model from disk"""
        self.model = joblib.load(self.model_path)
        print("✅ ML model loaded from disk")

# Global instance
ml_classifier = FileSecurityClassifier()

