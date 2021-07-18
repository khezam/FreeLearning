from app import mail
from flask_mail import Message

def send_email(name):
    msg = Message("Welcome!", sender=current_app.config['MAIL_DEFAULT_SENDER'], recipients=['flaskyproject@gmail.com'])
    msg.html = render_template('mail.html', name=name)
    mail.send(msg)
    return