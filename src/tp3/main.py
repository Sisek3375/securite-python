from src.tp3.utils.config import logger
from src.tp3.utils.session import Session


def main():
    logger.info("Starting TP3")

    ip = "31.220.95.27:9002"
    challenges = {
        "1": {"url": f"http://{ip}/captcha1/", "start": 1000}, # For each captcha, start is different
        "2": {"url": f"http://{ip}/captcha2/", "start": 2000},
        "3": {"url": f"http://{ip}/captcha3/", "start": 3000},
    }

    for i in challenges:
        url = challenges[i]["url"]
        start = challenges[i]["start"]
        session = Session(url, start)
        session.prepare_request()
        session.submit_request()

        while not session.process_response():
            session.prepare_request()
            session.submit_request()

        logger.info(f"Flag for {url} : {session.get_flag()}")


if __name__ == "__main__":
    main()
