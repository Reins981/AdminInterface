from flask_mail import Mail, Message
from flask import (
    url_for,
    render_template_string
)
from utils import (
    get_mail_server,
    get_mail_port,
    get_mail_password,
    get_mail_username,
    get_mail_tls_support,
    get_mail_default_sender
)

app = None
mail = None


def set_app(application):
    global app, mail
    app = application
    # Set up the SendGrid API client
    app.config['MAIL_SERVER'] = get_mail_server()
    app.config['MAIL_PORT'] = get_mail_port()
    app.config['MAIL_USE_TLS'] = get_mail_tls_support()
    app.config['MAIL_USERNAME'] = get_mail_username()
    app.config[
        'MAIL_PASSWORD'] = get_mail_password()
    app.config['MAIL_DEFAULT_SENDER'] = get_mail_default_sender()
    mail = Mail(app)


def create_mail_template(verification_link, logo_url):
    subject = "Verify Your Email Address - TLK AG"
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Email Verification</title>
    </head>
    <body style="font-family: Arial, sans-serif; margin: 0; padding: 0;">
        <div style="background-color: #f5f5f5;">
            <div style="background-color: #ffffff; margin: 0 auto; max-width: 600px;">
                <div style="padding: 20px 0; text-align: center;">
                    <img src="{logo_url}" alt="BACQROO Logo" style="max-width: 100%; height: auto;">
                </div>
                <div style="padding: 20px; text-align: center;">
                    <h1 style="color: #333333;">Welcome to TLK AG</h1>
                    <p style="color: #555555;">Please verify your email address by clicking the link below:</p>
                    <p><a href="{verification_link}" style="background-color: #007bff; color: #ffffff; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Verify Email</a></p>
                    <p style="color: #555555;">If you did not sign up for an account, you can ignore this email.</p>
                </div>
                <div style="padding: 20px; background-color: #f5f5f5; text-align: center;">
                    <p style="color: #777777;">If you have any questions or need assistance, please contact our support team at <a href="mailto:Superuser@tlk.com" style="color: #007bff;">Superuser@tlk.com</a>.</p>
                    <p style="color: #777777;">C. 42 Nte Manzana 141, Zazil-ha, 77720 Playa del Carmen, Q.R., Mexiko</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return subject, html_content


def create_mail_template_notification(user_name, logo_url):
    subject = "Document update - TLK AG"
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Email Notification</title>
    </head>
    <body style="font-family: Arial, sans-serif; margin: 0; padding: 0;">
        <div style="background-color: #f5f5f5;">
            <div style="background-color: #ffffff; margin: 0 auto; max-width: 600px;">
                <div style="padding: 20px 0; text-align: center;">
                    <img src="{logo_url}" alt="BACQROO Logo" style="max-width: 100%; height: auto;">
                </div>
                <div style="padding: 20px; text-align: center;">
                    <h1 style="color: #333333;">Welcome back to TLK AG {user_name}</h1>
                    <p style="color: #555555;">New documents are available in your account.</p>
                    <p style="color: #555555;">Please open your mobile App to access them.</p>
                </div>
                <div style="padding: 20px; background-color: #f5f5f5; text-align: center;">
                    <p style="color: #777777;">If you have any questions or need assistance, please contact our support team at <a href="mailto:Superuser@tlk.com" style="color: #007bff;">Superuser@tlk.com</a>.</p>
                    <p style="color: #777777;">C. 42 Nte Manzana 141, Zazil-ha, 77720 Playa del Carmen, Q.R., Mexiko</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return subject, html_content


def send_notification_mail(user_name, email_recipient):
    global mail
    if mail:
        # Render and send the email using Flask's render_template_string function
        logo_url = url_for('logo', filename='images/logo.png', _external=True)
        subject, html_content = create_mail_template_notification(user_name, logo_url)
        rendered_html = render_template_string(html_content)

        msg = Message(subject, recipients=[email_recipient])
        msg.html = rendered_html
        # Send the email
        try:
            mail.send(msg)
            message = f'Notification email for user {user_name} sent successfully'
            return 'success', message
        except Exception as e:
            return 'failed', str(e)
    return 'failed', 'Mail is not initialized'


def send_verify_user_mail(user_name, verification_link, email_recipient):
    global mail
    if mail:
        # Render and send the email using Flask's render_template_string function
        logo_url = url_for('logo', filename='images/logo.png', _external=True)
        subject, html_content = create_mail_template(verification_link, logo_url)
        rendered_html = render_template_string(html_content)

        msg = Message(subject, recipients=[email_recipient])
        msg.html = rendered_html
        # Send the email
        try:
            mail.send(msg)
            message = (f'User `{user_name}` created. '
                       f'Notification email sent successfully')
            return 'success', message
        except Exception as e:
            return 'failed', str(e)
    return 'failed', 'Mail is not initialized'
