import smtplib
from email.mime.text import MIMEText
from typing import List

from db import Sender


def send_email(sender: Sender, to_addr: List[str], mail: MIMEText):
    from_addr = sender.email
    password = sender.pwd
    smtp_server = sender.smtp_server
    smtp_port = sender.smtp_port
    mail['From'] = from_addr
    mail['To'] = ', '.join(to_addr)
    server = smtplib.SMTP_SSL(smtp_server, smtp_port)
    server.login(from_addr, password)
    server.sendmail(from_addr, to_addr, mail.as_string())
    server.quit()
