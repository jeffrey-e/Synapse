import logging
import smtplib
from email.message import EmailMessage
import ssl
import re

class SMTPConnector:
    'AzureSentinelConnector connector'

    def __init__(self, cfg):
        """
            Class constuctor

            :param cfg: synapse configuration
            :type cfg: ConfigParser

            :return: Object AzureSentinelConnector
            :rtype: AzureSentinelConnector
        """
        self.logger = logging.getLogger(__name__)
        self.cfg = cfg

        self.smtp_host = self.cfg.get("SMTP", "host", fallback="localhost")
        self.smtp_port = self.cfg.get("SMTP", "port", fallback="25")
        self.mail_from = self.cfg.get("SMTP", "from", fallback="synapse@localhost")
        self.smtp_user = self.cfg.get("SMTP", "user", fallback=None)
        self.smtp_pwd = self.cfg.get("SMTP", "password", fallback=None)

    def sendMail(self, recipient, title, body):

        mail_to = recipient

        msg = EmailMessage()
        msg["Subject"] = title
        msg["From"] = self.mail_from
        msg["To"] = mail_to
        msg.set_content(body)

        if self.smtp_user and self.smtp_pwd:
            try:
                context = ssl.create_default_context()

                # STANDARD CONNECTION, TRY ADDING TLS
                with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                    server.ehlo()
                    server.starttls(context=context)
                    server.ehlo()
                    server.login(self.smtp_user, self.smtp_pwd)
                    server.send_message(msg, self.mail_from, [mail_to])

                # SMTP_SSL CONNECTION
            except smtplib.SMTPServerDisconnected:
                with smtplib.SMTP_SSL(
                    self.smtp_host, self.smtp_port, context=context
                ) as server:
                    server.login(self.smtp_user, self.smtp_pwd)
                    server.send_message(msg, self.mail_from, [mail_to])

            except Exception:
                # STANDARD CONNECTION WITHOUT TLS
                with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                    server.ehlo()
                    server.login(self.smtp_user, self.smtp_pwd)
                    try:
                        server.send_message(msg, self.mail_from, [mail_to])
                    except Exception as e:
                        self.logger.error("Received an error while trying to send an email: {e}")
                        return

        else:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                try:
                    server.send_message(msg, self.mail_from, [mail_to])
                except smtplib.SMTPServerDisconnected:
                    self.logger.error("The server is not connecting properly. Please check your configuration")
                    return
                except Exception as e:
                    self.logger.error("Received an error while trying to send an email: {e}")
                    return

        self.logger.info(f"Succesfully sent email '{title}' to '{mail_to}'")

    def escapeUrls(self, url_string):
        # with valid conditions for urls in string
        regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
        splitted_string = re.split(regex,url_string)
        print(splitted_string)
        escaped_string = ""
        for count,partial_string in enumerate(splitted_string):
            if count == 0:
                escaped_string += partial_string
            if count == 1:
                escaped_string += partial_string.replace(".", "(.)")
            if count > 1 and partial_string:
                another_splitted_string = self.escapeUrls(partial_string)
                if another_splitted_string and len(another_splitted_string) > 1:
                    print(f"another: {another_splitted_string}")
                    escaped_string += another_splitted_string
                else:
                    escaped_string += partial_string
        return escaped_string
