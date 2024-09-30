import telebot
import json
import os
import random
import string
import time
from functools import wraps
from typing import Callable, Tuple
import requests
from fake_useragent import UserAgent
from faker import Faker
from loguru import logger

# Your Telegram bot token
BOT_TOKEN = '7876931785:AAGHo9zMMbEQ6Fr5ESMhi2ehSnLxH-c_FiQ'
AUTHORIZED_USERS = [7472978113]  # Replace with actual Telegram user IDs of authorized users
bot = telebot.TeleBot(BOT_TOKEN)

CAPTCHA_FILE = 'captcha.txt'

standart_header = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Content-Type": "application/json",
    "Connection": "keep-alive",
    "Host": "proxy.webshare.io",
    "Origin": "https://proxy2.webshare.io",
    "Referer": "https://proxy2.webshare.io/",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-site",
    "Pragma": "no-cache",
    "Cache-Control": "no-cache",
    "TE": "trailers",
}

fake_useragent = UserAgent()
fake = Faker()
request_session = requests.Session()
request_session.headers = standart_header


def authorization_required(f):
    @wraps(f)
    def decorated(message):
        if message.from_user.id not in AUTHORIZED_USERS:
            bot.send_message(message.chat.id, "🚫 Unauthorized access.")
            return
        return f(message)
    return decorated

@bot.message_handler(commands=['start'])
def start_command(message):
    bot.send_message(
        message.chat.id,
        "👋 Welcome to the Proxy Management Bot! Available commands:\n"
        "/token {token} - Add Recaptcha token\n"
        "/proxy - Create Webshare account and get proxy\n"
    )

@bot.message_handler(commands=['token'])
@authorization_required
def token_command(message):
    try:
        token = message.text.split(' ', 1)[1]
        with open(CAPTCHA_FILE, 'a') as file:
            file.write(token + '\n')
        bot.send_message(message.chat.id, "✅ Token saved successfully.")
    except IndexError:
        bot.send_message(message.chat.id, "⚠️ Please provide a valid token format: /token {your_token}")

def read_and_pop_token() -> str:
    """
    Reads the first token from the captcha.txt file and removes it from the file.
    """
    if not os.path.isfile(CAPTCHA_FILE):
        return None

    with open(CAPTCHA_FILE, 'r') as file:
        tokens = file.readlines()

    if not tokens:
        return None

    # Get the first token and remove it from the list
    token = tokens[0].strip()
    tokens = tokens[1:]

    # Write the remaining tokens back to the file
    with open(CAPTCHA_FILE, 'w') as file:
        file.writelines(tokens)

    return token

@bot.message_handler(commands=['proxy'])
@authorization_required
def proxy_command(message):
    try:
        bot.send_message(message.chat.id, "🔄 Creating Webshare account and generating proxies...")
        account_token, email, password, proxy_list = create_webshare_account_and_get_proxies()
        proxy_output = "\n".join(proxy_list)

        bot.send_message(
            message.chat.id, 
            f"✅ Account created successfully!\n"
            f"✉️ Email: {email}\n"
            f"🔐 Password: {password}\n"
            f"🌐 Proxies:\n{proxy_output}\n"
            "⚠️ Please keep your credentials secure!"
        )

        # Save the created accounts to a file (optional)
        with open(f"webshare-{int(time.time())}.txt", "a") as file:
            json.dump({"email": email, "password": password, "proxies": proxy_list}, file)
            file.write("\n")

    except Exception as e:
        bot.send_message(message.chat.id, f"❌ Error: {str(e)}")

def create_webshare_account_and_get_proxies():
    token = read_and_pop_token()
    if not token:
        raise ValueError("🚫 No Recaptcha tokens available. Please add one using /token {your_token}.")

    # Use the token to create the account
    account_token, email, password = register_acc(lambda: token)
    proxy_download_token = get_proxy_download_token(account_token)
    proxy_list = get_proxy(proxy_download_token)

    return account_token, email, password, proxy_list

def _update_random_proxy(proxy_file_name: str = "1", proxy_type: str = "socks5"):
    return
    if not os.path.isfile(proxy_file_name):
        logger.warning(
            "🚫 No proxy file list was found. Using Webshare without proxy can lead to multiple throttle bans."
        )
        return
    with open(proxy_file_name) as file:
        proxy_list = file.readlines()
        random_proxy = random.choice(proxy_list)
    proxy = f"{proxy_type}://{random_proxy.strip()}"
    request_session.proxies.update({"http": proxy, "https": proxy})

def temporary_cache(access_count: int = 2):
    def decorator(func):
        func.cache = None
        func.call_count = 0

        @wraps(func)
        def inner(*args, **kwargs):
            if not func.cache or func.call_count == access_count:
                func.cache = func(*args, **kwargs)
                func.call_count = 1
            else:
                func.call_count += 1
            return func.cache

        return inner

    return decorator

def _update_random_user_agent():
    request_session.headers = {"User-Agent": fake_useragent.random}

def _random_char(char_num) -> str:
    return "".join(random.choice(string.ascii_letters) for _ in range(char_num))

def _random_email(email_site: str = None) -> str:
    famous_email_site_list = ["google.com", "yandex.com", "mail.com"]

    if not email_site:
        email_site = random.choice(famous_email_site_list)

    return f"{_random_char(12)}@{email_site}"

def _random_password() -> str:
    return _random_char(15)

def register_acc(
    _recaptcha_token_provider: Callable,
    _random_email_provider: Callable = _random_email,
    _random_password_provider: Callable = _random_password,
) -> Tuple[str, str, str]:
    random_email = _random_email_provider()
    random_password = _random_password_provider()

    while True:
        try:
            recaptcha_code = _recaptcha_token_provider()
            response = request_session.post(
                "https://proxy.webshare.io/api/v2/register/",
                json={
                    "email": random_email,
                    "password": random_password,
                    "recaptcha": recaptcha_code,
                    "tos_accepted": True,
                    "marketing_email_accepted": False,
                },
            )
            response_json = response.json()

            if response.status_code != 200:
                if response_json.get("recaptcha"):
                    if response_json["recaptcha"][0]["code"] == "captcha_invalid":
                        logger.error(f"🚫 Invalid Recaptcha token: {response_json}")
                        return None, None, None
                raise ValueError(f"❌ Error: can't register account. Status code: {response.status_code}. Info: {response_json}")

            return response_json["token"], random_email, random_password

        except Exception as ex:
            logger.exception(ex)
            _update_random_proxy()

def get_proxy_download_token(account_token: str) -> str:
    auth_header = {"Authorization": f"Token {account_token}"}
    response = request_session.get(
        "https://proxy.webshare.io/api/v2/proxy/config/", headers=auth_header
    )
    response_json = response.json()

    if not response_json.get("proxy_list_download_token"):
        raise ValueError(f"❌ Error: can't parse proxy download token. Info: {response_json}")

    return response_json["proxy_list_download_token"]

def get_proxy(proxy_download_token: str) -> list:
    response = requests.get(
        f"https://proxy.webshare.io/api/v2/proxy/list/download/{proxy_download_token}/-/any/username/direct/-/"
    )
    return response.text.split("\n")

# Start the bot
bot.polling()
