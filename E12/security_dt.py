import pandas as pd
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import RepeatedStratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score


DATASET_PATH = "DATASET.csv"   # <-- your actual file


def load_dataset(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    return df


def prepare_xy(df: pd.DataFrame):
    # label is 'Type'
    if "Type" not in df.columns:
        raise ValueError("Expected a 'Type' column in the dataset.")

    y = df["Type"]

    # drop label from features
    X = df.drop(columns=["Type"])

    # do NOT include URL as a feature
    if "URL" in X.columns:
        X = X.drop(columns=["URL"])

    # fill numeric NaNs 
    for col in X.columns:
        if pd.api.types.is_numeric_dtype(X[col]):
            X[col] = X[col].fillna(0)

    # encode object/string columns into category codes
    for col in X.columns:
        if X[col].dtype == "object":
            X[col] = X[col].astype("category").cat.codes
            # if there were unseen/missing into -1; make it 0
            X[col] = X[col].replace(-1, 0)

    return X, y


def run_10x10_cv(X, y, out_file="classification_results.txt"):
    rskf = RepeatedStratifiedKFold(
        n_splits=10,
        n_repeats=10,
        random_state=42
    )

    accs, precs, recs, f1s = [], [], [], []
    lines = []
    fold_no = 1

    for train_idx, test_idx in rskf.split(X, y):
        X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
        y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

        clf = DecisionTreeClassifier(
            criterion="entropy",  # Item-5: use entropy
            random_state=42
        )
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, average="macro", zero_division=0)
        rec = recall_score(y_test, y_pred, average="macro", zero_division=0)
        f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)

        accs.append(acc)
        precs.append(prec)
        recs.append(rec)
        f1s.append(f1)

        lines.append(
            f"Fold {fold_no:03d} -> "
            f"Accuracy: {acc:.4f}, Precision: {prec:.4f}, Recall: {rec:.4f}, F1: {f1:.4f}"
        )
        fold_no += 1

    lines.append("\n===== OVERALL (10x10-fold CV) =====")
    lines.append(f"Average Accuracy: {np.mean(accs):.4f}")
    lines.append(f"Average Precision (macro): {np.mean(precs):.4f}")
    lines.append(f"Average Recall (macro): {np.mean(recs):.4f}")
    lines.append(f"Average F1 (macro): {np.mean(f1s):.4f}")

    with open(out_file, "w") as f:
        for line in lines:
            f.write(line + "\n")

    print(f"[INFO] Wrote CV metrics to {out_file}")


def write_feature_importances(X, y, out_file="feature_importance.txt"):
    clf = DecisionTreeClassifier(
        criterion="entropy",
        random_state=42
    )
    clf.fit(X, y)

    importances = clf.feature_importances_
    names = X.columns

    pairs = sorted(
        zip(names, importances),
        key=lambda x: x[1],
        reverse=True
    )

    with open(out_file, "w") as f:
        f.write("Feature Importances (Decision Tree, entropy)\n")
        for name, imp in pairs:
            f.write(f"{name}: {imp:.6f}\n")

    print(f"[INFO] Wrote feature importances to {out_file}")


def main():
    df = load_dataset(DATASET_PATH)
    X, y = prepare_xy(df)

    # Item-3: 10x10 CV into classification_results.txt
    run_10x10_cv(X, y, out_file="classification_results.txt")

    # Item-4: feature importance into feature_importance.txt
    write_feature_importances(X, y, out_file="feature_importance.txt")


if __name__ == "__main__":
    main()
