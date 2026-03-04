import requests
from src.tp3.utils.captcha import Captcha


class Session:
    """
    Class representing a session to solve a captcha and submit a flag.

    Attributes:
        url (str): The URL of the captcha.
        captcha_value (str): The value of the solved captcha.
        flag_value (str): The value of the flag to submit.
        valid_flag (str): The valid flag obtained after processing the response.
    """

    def __init__(self, url, start_flag=1000):
        """
        Initializes a new session with the given URL.

        Args:
            url (str): The URL of the captcha.
            start_flag (int): The starting flag value.
        """
        self.url = url
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""
        self.http_session = requests.Session()
        self.response = None
        self.current_flag = start_flag

    def prepare_request(self):
        """
        Prepares the request for sending by capturing and solving the captcha.
        """
        captcha = Captcha(self.url, self.http_session)
        captcha.capture()
        captcha.solve()

        self.captcha_value = captcha.get_value()
        self.flag_value = self.current_flag
        self.current_flag += 1

    def submit_request(self):
        """
        Sends the flag and captcha.
        """
        self.response = self.http_session.post(self.url, data={
            "flag": self.flag_value,
            "captcha": self.captcha_value,
            "submit": "Submit"
        })

    def process_response(self):
        """
        Processes the response.
        """
        if "Invalid captcha" in self.response.text:
            return False
        if "Incorrect flag" in self.response.text:
            return False
        self.valid_flag = self.flag_value
        return True

    def get_flag(self):
        """
        Returns the valid flag.
        """
        return self.valid_flag
