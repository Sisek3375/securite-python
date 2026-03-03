from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report


def main():
    logger.info("Starting TP1")

    capture = Capture()
    try:
        capture.capture_traffic()
    except KeyboardInterrupt:
        logger.info("Capture stopped by the user")

    report = Report(capture, "src/tp1/report.pdf")
    report.save()
    logger.info("Report saved in report.pdf")


if __name__ == "__main__":
    main()