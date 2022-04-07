import pandas

ATTR_TUPLE = ("REFER TO COMMIT",
              "REFER TO ISSUE",
              "REFER TO RELEASE",
              "REFER TO ADVISORY",
              "REFER TO PULL",
              "REFER TO HUNTR")

if __name__ == "__main__":
    data_frame = pandas.read_csv("../dataset/report_fix_survey.csv")
    rows = data_frame.shape[0]
    data_frame["PUBLISH YEAR"] = data_frame["CVE ID"].apply(lambda x: int(x["CVE ID"].split("-")[1]))
    new_dataframe = data_frame.loc[:, ATTR_TUPLE]
    data_frame2 = pandas.read_csv("../dataset/report_fix_survey2.csv")
    rows2 = data_frame2.shape[0]
    data_frame2["PUBLISH YEAR"] = data_frame2["CVE ID"].apply(lambda x: int(x["CVE ID"].split("-")[1]))
    data_frame2["PUBLISH YEAR"] = data_frame2.apply(lambda x: x["CVE ID"].split("-")[1])
    new_dataframe2 = data_frame2.loc[:, ATTR_TUPLE]
    commit_count = data_frame["REFER TO COMMIT"].sum()
    release_count = data_frame["REFER TO RELEASE"].sum()
    issue_count = data_frame["REFER TO ISSUE"].sum()
    advisory_count = data_frame["REFER TO ADVISORY"].sum()
    pull_count = data_frame["REFER TO PULL"].sum()
    huntr_count = data_frame["REFER TO HUNTR"].sum()
    new_dataframe["VALID REFERENCE"] = new_dataframe.apply(lambda x: x.sum(), axis=1)
    valid_row_count = len(new_dataframe[new_dataframe["VALID REFERENCE"] == 0].index.tolist())
    commit_count2 = data_frame2["REFER TO COMMIT"].sum()
    release_count2 = data_frame2["REFER TO RELEASE"].sum()
    issue_count2 = data_frame2["REFER TO ISSUE"].sum()
    pull_count2 = data_frame2["REFER TO PULL"].sum()
    advisory_count2 = data_frame2["REFER TO ADVISORY"].sum()
    huntr_count2 = data_frame2["REFER TO HUNTR"].sum()
    new_dataframe2["VALID REFERENCE"] = new_dataframe.apply(lambda x: x.sum(), axis=1)
    valid_row_count2 = len(new_dataframe2[new_dataframe2["VALID REFERENCE"] == 0].index.tolist())
    data_frame_after_2020 = data_frame[data_frame["PUBLISH YEAR"] >= 2020]
    data_frame_after_2020_2 = data_frame[data_frame2["PUBLISH YEAR"] >= 2020]
    print(f"CVE refers to commit: {commit_count}")
    print(f"CVE refers to issue: {issue_count}")
    print(f"CVE refers to release: {release_count}")
    print(f"CVE refers to security advisory: {advisory_count}")
    print(f"CVE refers to pull: {pull_count}")
    print(f"CVE refers to huntr: {huntr_count}")
    print("----------------------------------")
    print(f"CVE refers to commit: {commit_count2}")
    print(f"CVE refers to issue: {issue_count2}")
    print(f"CVE refers to release: {release_count2}")
    print(f"CVE refers to security advisory: {advisory_count2}")
    print(f"CVE refers to pull: {pull_count2}")
    print(f"CVE refers to huntr: {huntr_count2}")
