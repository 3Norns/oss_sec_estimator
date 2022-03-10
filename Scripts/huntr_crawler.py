from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions
from time import sleep

# def get_record_date_xpath(index):
#     return "//table[@id='hacktivity-table']/tbody/tr[" + index + "]/tr/td/div/dov/div/div"

driver = webdriver.Chrome()
driver.get("https://huntr.dev/bounties/hacktivity/")

# 定位记录表
hacktivity_table_xpath = "//table[@id='hacktivity-table']/tbody/tr"

# 定位相关记录CVE编号
cve_number_xpath = "//td/div/div[2]/div[2]/a[2]"

# 记录相关记录的发布日期，在此我们只关心2020年后发布的记录
release_date_xpath = "//td/div/div/div/div"

# 定位Github项目相对路径
project_relative_path_xpath = "//td/div/div/div/span"

# 定位漏洞描述相关信息
vul_description_xpath = "//td/div/div/div/a"

wait = WebDriverWait(driver, 10)
wait.until(expected_conditions.presence_of_element_located((By.ID, "show-more-button")))

show_more_button = driver.find_element_by_id("show-more-button")

total_record = 0

hacktivity_table = driver.find_element_by_xpath(hacktivity_table_xpath)

while(True):
    first_record_date = hacktivity_table[total_record].find_element_by_xpath(release_date_xpath)
    last_record_date = hacktivity_table[len(hacktivity_table)].find_element_by_xpath(release_date_xpath)
    first_record_release_year = first_record_date.strip(" ").split("\s+")
    last_record_release_year = last_record_date.strip(" ").split("\s+")

driver.quit()
