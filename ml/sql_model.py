import pickle
import csv
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
from ml.features import extract_features


MODEL_PATH = "ml/models/sql.pkl"


def train_sql_model(dataset_path: str):
    payloads = []
    labels = []

    with open(dataset_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            payloads.append(row["payload"])
            labels.append(int(row["label"]))

    X = [extract_features(p) for p in payloads]

    vectorizer = DictVectorizer(sparse=False)
    X_vec = vectorizer.fit_transform(X)

    model = LogisticRegression(max_iter=1000)
    model.fit(X_vec, labels)

    with open(MODEL_PATH, "wb") as f:
        pickle.dump((model, vectorizer), f)


def ml_detect_sql(payload: str):
    with open(MODEL_PATH, "rb") as f:
        model, vectorizer = pickle.load(f)

    features = extract_features(payload)
    X_vec = vectorizer.transform([features])

    prob = model.predict_proba(X_vec)[0][1]
    return prob >= 0.5, prob
