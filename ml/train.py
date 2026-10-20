from ml.sql_model import train_sql_model
from ml.xss_model import train_xss_model

if __name__ == "__main__":
    train_sql_model("data/datasets/sql.csv")
    train_xss_model("data/datasets/xss.csv")
    print("SQL & XSS models trained successfully.")
