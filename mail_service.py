#!/usr/bin/env python3
"""mail service"""
from flask_mail import Mail, Message
from flask import current_app

mail = Mail()

def send_email(rec_email, subject, template_body):
    """
    Sends an email using Flask-Mail.
    Args:
        rec_email (str): Reciever's email address.
        subject (str): Email subject.
        template_body (str): The body of the email
    """
    msg = Message(
        subject=subject,
        sender=current_app.config['MAIL_DEFAULT_SENDER'],
        recipients=[rec_email]
    )
    msg.body = template_body

    try:
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f"Error sending email to {rec_email}: {e}")
        return False