import os
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import joblib


def load_data(path='phishing.csv'):
    df = pd.read_csv(path)
    # Ensure columns are named 'text' and 'label'
    if 'text' not in df.columns:
        if 'email' in df.columns:
            df = df.rename(columns={'email': 'text'})
        elif 'content' in df.columns:
            df = df.rename(columns={'content': 'text'})
    if 'label' not in df.columns:
        if 'is_phishing' in df.columns:
            df = df.rename(columns={'is_phishing': 'label'})
    df = df[['text', 'label']].dropna()
    return df


def train_and_save(model_path='model.pkl', data_path='phishing.csv', test_size=0.2, random_state=42):
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Data file not found: {data_path}")
    df = load_data(data_path)
    X = df['text'].astype(str)
    y = df['label']

    # Encode labels to numeric
    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    # Split
    stratify = y_enc if len(le.classes_) > 1 else None
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=test_size, random_state=random_state, stratify=stratify
    )

    # Vectorizer shared configuration
    vectorizer_args = {'stop_words': 'english', 'max_features': 5000}

    # Define models
    models = {
        'nb': MultinomialNB(),
        'lr': LogisticRegression(max_iter=1000, random_state=42),
        'rf': RandomForestClassifier(n_estimators=100, random_state=42)
    }

    pipelines = {}
    metrics = {}

    for name, clf in models.items():
        print(f"Training {name} classifier...")
        pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(**vectorizer_args)),
            ('clf', clf)
        ])
        pipeline.fit(X_train, y_train)
        pipelines[name] = pipeline

        # Predict
        y_pred = pipeline.predict(X_test)

        # Calculate metrics
        acc = accuracy_score(y_test, y_pred)
        if len(le.classes_) == 2:
            precision = precision_score(y_test, y_pred, pos_label=1, zero_division=0)
            recall = recall_score(y_test, y_pred, pos_label=1, zero_division=0)
            f1 = f1_score(y_test, y_pred, pos_label=1, zero_division=0)
        else:
            precision = precision_score(y_test, y_pred, average='macro', zero_division=0)
            recall = recall_score(y_test, y_pred, average='macro', zero_division=0)
            f1 = f1_score(y_test, y_pred, average='macro', zero_division=0)
        
        cm = confusion_matrix(y_test, y_pred).tolist()

        metrics[name] = {
            'accuracy': float(acc),
            'precision': float(precision),
            'recall': float(recall),
            'f1': float(f1),
            'confusion_matrix': cm
        }

        print(f"[{name}] Acc: {acc:.4f}, Prec: {precision:.4f}, Rec: {recall:.4f}, F1: {f1:.4f}")

    # Save everything
    save_obj = {
        'models': pipelines,
        'metrics': metrics,
        'label_encoder': le
    }
    
    joblib.dump(save_obj, model_path)
    print(f"Successfully saved all pipelines and metrics to {model_path}")
    return save_obj


if __name__ == '__main__':
    train_and_save()
