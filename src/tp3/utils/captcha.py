import pytesseract
from PIL import Image
import io

class Captcha:
    def __init__(self, url, http_session):
        self.url = url
        self.http_session = http_session
        self.image = ""
        self.value = ""

    def solve(self):
        """
        Fonction permettant la résolution du captcha.
        """

        image = Image.open(io.BytesIO(self.image))
        self.value = pytesseract.image_to_string(image).strip()

    def capture(self):
        """
        Fonction permettant la capture du captcha.
        """
        response = self.http_session.get("http://31.220.95.27:9002/captcha.php")
        self.image = response.content

    def get_value(self):
        """
        Fonction retournant la valeur du captcha
        """
        return self.value
