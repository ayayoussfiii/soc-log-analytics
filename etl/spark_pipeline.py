from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    StructType, StructField, StringType,
    IntegerType, ArrayType, TimestampType
)
from pyspark.sql.window import Window
import os
from dotenv import load_dotenv

load_dotenv()

# ─── Schéma du log normalisé ──────────────────────────────────────────────────
LOG_SCHEMA = StructType([
    StructField("timestamp",      StringType(),           True),
    StructField("hostname",       StringType(),           True),
    StructField("ip",             StringType(),           True),
    StructField("user",           StringType(),           True),
    StructField("process",        StringType(),           True),
    StructField("pid",            StringType(),           True),
    StructField("message",        StringType(),           True),
    StructField("severity",       IntegerType(),          True),
    StructField("severity_label", StringType(),           True),
    StructField("format",         StringType(),           True),
    StructField("raw",            StringType(),           True),
    StructField("parsed_at",      StringType(),           True),
    StructField("tags",           ArrayType(StringType()), True),
])


# ─── Initialiser Spark ────────────────────────────────────────────────────────
def create_spark_session(app_name: str = "SOC-Log-Analytics") -> SparkSession:
    return SparkSession.builder \
        .appName(app_name) \
        .master(os.getenv("SPARK_MASTER", "local[*]")) \
        .config("spark.sql.shuffle.partitions", "4") \
        .config("spark.driver.memory", "2g") \
        .getOrCreate()


# ─── Charger les logs JSON ────────────────────────────────────────────────────
def load_logs(spark: SparkSession, path: str):
    return spark.read \
        .schema(LOG_SCHEMA) \
        .json(path)


# ─── Nettoyage & casting ──────────────────────────────────────────────────────
def clean_logs(df):
    return df \
        .withColumn("timestamp", F.to_timestamp("timestamp")) \
        .withColumn("severity",  F.coalesce(F.col("severity"), F.lit(6))) \
        .filter(F.col("message").isNotNull()) \
        .filter(F.col("timestamp").isNotNull())


# ─── Window Aggregations ──────────────────────────────────────────────────────
def compute_window_features(df):
    """
    Calcule sur une fenêtre glissante de 5 minutes par IP :
    - Nombre de tentatives
    - Nombre d'utilisateurs distincts
    - Sévérité moyenne
    """
    window_5min = Window \
        .partitionBy("ip") \
        .orderBy(F.col("timestamp").cast("long")) \
        .rangeBetween(-300, 0)  # 5 minutes en secondes

    return df \
        .withColumn("attempts_5min",
            F.count("*").over(window_5min)) \
        .withColumn("distinct_users_5min",
            F.approx_count_distinct("user").over(window_5min)) \
        .withColumn("avg_severity_5min",
            F.avg("severity").over(window_5min))


# ─── Feature Engineering ──────────────────────────────────────────────────────
def compute_features(df):
    """
    Ajoute les features pour le modèle ML :
    - brute_force_flag
    - hour_of_day
    - is_night
    - has_ip
    """
    return df \
        .withColumn("brute_force_flag",
            F.when(F.array_contains(F.col("tags"), "brute_force"), 1).otherwise(0)) \
        .withColumn("privilege_flag",
            F.when(F.array_contains(F.col("tags"), "privilege_esc"), 1).otherwise(0)) \
        .withColumn("hour_of_day",
            F.hour("timestamp")) \
        .withColumn("is_night",
            F.when((F.col("hour_of_day") >= 22) | (F.col("hour_of_day") <= 6), 1).otherwise(0)) \
        .withColumn("has_ip",
            F.when(F.col("ip").isNotNull(), 1).otherwise(0))


# ─── Agrégation par IP ────────────────────────────────────────────────────────
def aggregate_by_ip(df):
    return df.groupBy("ip").agg(
        F.count("*").alias("total_events"),
        F.sum("brute_force_flag").alias("brute_force_count"),
        F.sum("privilege_flag").alias("privilege_count"),
        F.avg("severity").alias("avg_severity"),
        F.max("timestamp").alias("last_seen"),
        F.min("timestamp").alias("first_seen"),
        F.collect_set("user").alias("users_seen"),
        F.collect_set("hostname").alias("hosts_seen")
    )


# ─── Sauvegarder en Parquet ───────────────────────────────────────────────────
def save_parquet(df, path: str):
    df.write \
        .mode("overwrite") \
        .parquet(path)
    print(f"[✓] Sauvegardé : {path}")


# ─── Pipeline complet ─────────────────────────────────────────────────────────
def run_pipeline(input_path: str, output_path: str):
    print("[*] Démarrage du pipeline ETL PySpark...")

    spark = create_spark_session()

    print("[*] Chargement des logs...")
    df = load_logs(spark, input_path)

    print("[*] Nettoyage...")
    df = clean_logs(df)

    print("[*] Window aggregations...")
    df = compute_window_features(df)

    print("[*] Feature engineering...")
    df = compute_features(df)

    print("[*] Sauvegarde features...")
    save_parquet(df, f"{output_path}/features")

    print("[*] Agrégation par IP...")
    df_agg = aggregate_by_ip(df)
    save_parquet(df_agg, f"{output_path}/ip_aggregates")

    print("[✓] Pipeline terminé !")
    spark.stop()


if __name__ == "__main__":
    import sys
    input_path  = sys.argv[1] if len(sys.argv) > 1 else "data/logs"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "data/output"
    run_pipeline(input_path, output_path)
