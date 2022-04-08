"""
This script is used for writing mysql data into csv
"""
import pymysql
import csv


def main(table_name, target_path):
    conn = pymysql.connect(
        host="localhost",
        user="root",
        password="SteinsGate0",
        database="oss_security_estimator",
        charset="utf8"
    )
    cursor = conn.cursor()
    cursor.execute(f"SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA ="
                   f" 'oss_security_estimator' AND TABLE_NAME = '{table_name}'")
    column_names = cursor.fetchall()
    label = []
    for column_name in column_names:
        label.append(column_name[0])
    cursor.execute(f"select * from {table_name}")
    data = cursor.fetchall()
    with open(target_path, "w", newline="") as t:
        writer = csv.writer(t)
        writer.writerow(label)
        writer.writerows(data)
    print("data has been written into csv file")


if __name__ == "__main__":
    main("project_cve_table", "D:/PycharmProjects/oss_sec_estimator/dataset/project_cve.csv")
