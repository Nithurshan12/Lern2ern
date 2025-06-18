import smtplib
import random
import time
from email.message import EmailMessage

# Configuration
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SENDER_EMAIL = 'your_email@gmail.com'   # Replace with sender's email
SENDER_PASSWORD = 'your_password'       # Replace with sender's email password

def generate_code(length=6):
    """Generate a random numeric verification code."""
    return ''.join(random.choices('0123456789', k=length))

def send_email(receiver_email, code):
    """Send the verification code to the user's email."""
    msg = EmailMessage()
    msg.set_content(f'Your verification code is: {code}')
    msg['Subject'] = 'Your Verification Code'
    msg['From'] = SENDER_EMAIL
    msg['To'] = receiver_email

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
    print(f"Verification code sent to {receiver_email}")

def verify_code(input_code, actual_code, expiry_time, sent_time):
    """Check if code matches and is within expiry time."""
    current_time = time.time()
    if current_time - sent_time > expiry_time:
        return False, "Code expired"
    return input_code == actual_code, "Verified" if input_code == actual_code else "Incorrect code"

# Example usage
if __name__ == "__main__":
    receiver = input("Enter your email: ")
    code = generate_code()
    send_email(receiver, code)
    sent_time = time.time()
    expiry = 300  # 5 minutes

    input_code = input("Enter the verification code sent to your email: ")
    valid, message = verify_code(input_code, code, expiry, sent_time)
    print(message)
