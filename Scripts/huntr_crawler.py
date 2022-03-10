from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions
from time import sleep
from copy import deepcopy

def get_record_release_year(selenium_item):
    record_release_date = selenium_item.find_element_by_xpath(release_date_xpath).text
    record_release_year = int(record_release_date.strip().split()[2])
    return record_release_year

def trim_relative_path(project_relative_path):
    list = project_relative_path.split("/", 2)
    trimmed_path = list[0].strip() + "/" + list[1].strip()
    return trimmed_path

driver = webdriver.Chrome()
driver.get("https://huntr.dev/")
driver.get("https://huntr.dev/bounties/hacktivity/")

# locate hacktivity table
hacktivity_table_xpath = "//table[@id='hacktivity-table']/tbody/tr"

# locate relevant CVE number
cve_number_xpath = "./td/div/div[2]/div[2]/a[2]"

# locate relevant record's release day, we focus on record that release after 2020
release_date_xpath = "./td/div/div/div/div"

# locate relative path of the github project
project_relative_path_xpath = "./td/div/div/div/span"

# locate vulnerability description
vul_description_xpath = "./td/div/div/div/a"

wait = WebDriverWait(driver, 10)
wait.until(expected_conditions.presence_of_element_located((By.ID, "show-more-button")))

show_more_button = driver.find_element_by_id("show-more-button")

total_record = 0
record_table = []

hacktivity_table = driver.find_elements_by_xpath(hacktivity_table_xpath)

while True:
    first_record_release_year = get_record_release_year(hacktivity_table[total_record])
    last_record_release_year = get_record_release_year(hacktivity_table[len(hacktivity_table) - 1])

    if last_record_release_year >= 2020:
        for record in hacktivity_table[total_record : ]:
            row = []
            project_relative_path = record.find_element_by_xpath(project_relative_path_xpath).text
            trimmed_path = trim_relative_path(project_relative_path)
            cve_number = record.find_element_by_xpath(cve_number_xpath).text
            vul_description = record.find_element_by_xpath(vul_description_xpath).text
            date = record.find_element_by_xpath(release_date_xpath).text

            row.append(trimmed_path)
            row.append(cve_number)
            row.append(vul_description)
            row.append(date)
            record_table.append(row.copy())

        total_record = len(hacktivity_table)

        # 页面记录添加
        show_more_button.click()
        sleep(5)
        hacktivity_table = driver.find_elements_by_xpath(hacktivity_table_xpath)
        if len(hacktivity_table) <= total_record:
            break

    elif first_record_release_year >= 2020 and last_record_release_year < 2020:
        flag = False
        for record in hacktivity_table[total_record : ]:
            this_record_release_date = get_record_release_year(record)
            if this_record_release_date >= 2020:
                row = []
                project_relative_path = record.find_element_by_xpath(project_relative_path_xpath).text
                trimmed_path = trim_relative_path(project_relative_path)
                cve_number = record.find_element_by_xpath(cve_number_xpath).text
                vul_description = record.find_element_by_xpath(vul_description_xpath).text
                date = record.find_element_by_xpath(release_date_xpath).text

                row.append(trimmed_path)
                row.append(cve_number)
                row.append(vul_description)
                row.append(date)
                record_table.append(row)

                total_record += 1
            else:
                flag = True
                break
        if flag:
            break

    else:
        break

    print("table rows:", total_record)


driver.quit()
