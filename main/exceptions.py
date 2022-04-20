class PageOpenException(Exception):
    def __init__(self, url, status_code):
        self.url = url
        self.status_code

    def __str__(self):
        return f"URL {self.url} did NOT open properly. Status code: {str(self.status_code)}"


class NVDQueryException(Exception):
    def __str__(self):
        return "Exception occurred when query NVD."


class NumberExceedCapException(Exception):
    def __str__(self):
        return "Very large number."


class URLException(Exception):
    pass
