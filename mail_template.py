
def create_mail_template(verification_link, logo_url):
    subject = "Verify Your Email Address - BACQROO Accounting"
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Email Verification</title>
    </head>
    <body style="font-family: Arial, sans-serif; margin: 0; padding: 0;">
        <table cellpadding="0" cellspacing="0" width="100%" style="background-color: #f5f5f5;">
            <tr>
                <td align="center" valign="top">
                    <table cellpadding="0" cellspacing="0" width="600" style="background-color: #ffffff;">
                        <tr>
                            <td align="center" valign="top" style="padding: 20px 0;">
                                <img src="{logo_url}" alt="BACQROO Logo" style="max-width: 150px;">
                            </td>

                        </tr>
                        <tr>
                            <td align="center" valign="top" style="padding: 20px;">
                                <h1 style="color: #333333;">Welcome to BACQROO Accounting</h1>
                                <p style="color: #555555;">Please verify your email address by clicking the link below:</p>
                                <p><a href="{verification_link}" style="background-color: #007bff; color: #ffffff; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email</a></p>
                                <p style="color: #555555;">If you did not sign up for an account, you can ignore this email.</p>
                            </td>
                        </tr>
                        <tr>
                            <td align="center" valign="top" style="padding: 20px; background-color: #f5f5f5;">
                                <p style="color: #777777;">If you have any questions or need assistance, please contact our support team at <a href="mailto:Serranop@bacqroo.com" style="color: #007bff;">Serranop@bacqroo.com</a>.</p>
                                <p style="color: #777777;">C. 42 Nte Manzana 141, Zazil-ha, 77720 Playa del Carmen, Q.R., Mexiko</p>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """
    return subject, html_content
