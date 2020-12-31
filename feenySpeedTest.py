#! python3.9



from selenium.webdriver import Chrome, ChromeOptions
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
from contextlib import contextmanager


@contextmanager
def get_chrome() -> Chrome:
    # https://docs.python.org/3.7/library/contextlib.html#contextlib.contextmanager
    opts = ChromeOptions()
    opts.headless = True
    opts.add_argument('--window-size=300,300')
    driver = Chrome(options=opts)

    #driver.set_window_position(400, 400, windowHandle='current') #works but opens then closes then opens in the right spot
    yield driver
    
    driver.close()

#     chrome_options = Options()
# chrome_options.add_argument("--window-size=1920,1080")
# driver = Chrome(chrome_options=chrome_options)


def wait_until_present(driver: Chrome, selector: str, timeout: int = 5):
    condition = EC.presence_of_element_located((By.CSS_SELECTOR, selector))
    try:
        WebDriverWait(driver, timeout).until(condition)
    except TimeoutException as e:
        raise LookupError(f'{selector} is not present after {timeout}s') from e


def extract_speed_info(soup: BeautifulSoup) -> dict:
    dl_speed = soup.select_one('#speed-value').text
    dl_unit = soup.select_one('#speed-units').text
    upload_speed = soup.select_one('#upload-value').text
    upload_unit = soup.select_one('#upload-units').text

    return {
        'Download: ': f'{dl_speed} {dl_unit}',
        'Upload: ': f'{upload_speed} {upload_unit}\n'
        #'download': f'{dl_speed} {dl_unit}'
    }

    # return {
    #     'download': f'{dl_speed} {dl_unit}'
    #     }


def run_speed_test() -> dict:
    with get_chrome() as driver:
        driver.get('https://fast.com')

        # wait at most 60s until upload results come in
        download_done_selector = '#speed-value.succeeded'
        upload_done_selector = '#upload-value.succeeded'
        #wait_until_present(driver, download_done_selector, timeout=60) #just download
        wait_until_present(driver, upload_done_selector, timeout=60)

        # this is the parent element that contains both download and upload results
        results_selector = '.speed-container'
        results_el = driver.find_element_by_css_selector(results_selector)
        results_html = results_el.get_attribute('outerHTML')

    # we're finished with chrome, let it close (by exiting with block)

    soup = BeautifulSoup(results_html, 'html.parser')
    info = extract_speed_info(soup)
    return info


if __name__ == '__main__':
    try:
        results = run_speed_test()
        print('Speed results:', results)
    except LookupError as e:
        print('Cannot get speed results')
        print(e)
        exit(1)

