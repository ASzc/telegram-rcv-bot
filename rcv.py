#!/usr/bin/env python3

import argparse
import asyncio
import base64
import configparser
import datetime
import io
import logging
import os
import ssl
import sys
import tempfile

# https://pypi.org/project/aiogram/
import aiogram
import aiogram.contrib.fsm_storage.redis
import aiogram.dispatcher
import aiogram.utils.executor

# https://pypi.org/project/cryptography/
import cryptography
import cryptography.x509.oid
import cryptography.hazmat.backends
import cryptography.hazmat.primitives
import cryptography.hazmat.primitives.asymmetric

log = logging.getLogger("rcv")

#
# Certificate generation
#

#
# Handlers
#

async def send_welcome(message: aiogram.types.Message):
    log.info(f"Sending welcome")
    await message.reply("Hi!\nI'm RankedPollBot!")

# TODO: can use `await message.dp.storage.redis()` to get a plain redis connection outside the FSM?

async def echo(message: aiogram.types.Message):
    log.info(f"Echo got: {message.text}")
    await message.reply(message.text)


#
# Main
#

def webhook_bot(config, register_callback, loop=None):
    # Read config
    api_token = config["auth"]["token"]

    redis_host = config["redis"]["host"]
    redis_port = int(config["redis"]["port"])
    redis_prefix = config["redis"]["prefix"]

    webhook_host = config["webhook"]["host"]
    webhook_port = int(config["webhook"]["port"])
    webhook_path = os.path.join(
        config["webhook"]["root"],
        base64.urlsafe_b64encode(os.urandom(21)).decode('ascii')
    )

    # Setup aiogram
    loop = loop or asyncio.get_event_loop()
    bot = aiogram.Bot(
        token=api_token,
        loop=loop,
    )
    storage = aiogram.contrib.fsm_storage.redis.RedisStorage2(
        host=redis_host,
        port=redis_port,
        prefix=redis_prefix,
        loop=loop,
    )
    dp = aiogram.dispatcher.Dispatcher(
        bot=bot,
        storage=storage,
        loop=loop,
    )
    # Hack to make handlers definable outside of local context
    bot.dp = dp

    # Register handlers
    register_callback(dp)

    # Set up HTTPS
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    webhook_certificate = None
    log.info("Generating self-signed certificate")
    # https://core.telegram.org/bots/self-signed
    key = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=cryptography.hazmat.backends.default_backend(),
    )
    with tempfile.TemporaryDirectory() as td:
        key_path = os.path.join(td, "key.pem")
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
                format=cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=cryptography.hazmat.primitives.serialization.NoEncryption(),
            ))
        name = cryptography.x509.Name([
            cryptography.x509.NameAttribute(
                cryptography.x509.oid.NameOID.COMMON_NAME,
                webhook_host
            ),
        ])
        cert = cryptography.x509.CertificateBuilder()\
            .subject_name(name)\
            .issuer_name(name)\
            .public_key(key.public_key())\
            .serial_number(cryptography.x509.random_serial_number())\
            .not_valid_before(datetime.datetime.utcnow())\
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365*5))\
            .sign(
                key,
                cryptography.hazmat.primitives.hashes.SHA256(),
                cryptography.hazmat.backends.default_backend(),
            )
        cert_bytes = cert.public_bytes(
            encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
        )
        webhook_certificate=io.BytesIO(cert_bytes)
        crt_path = os.path.join(td, "cert.pem")
        with open(crt_path, "wb") as f:
            f.write(cert_bytes)

        ssl_context.load_cert_chain(crt_path, key_path)

    # Define startup and shutdown actions
    async def on_startup(dp):
        url = f"https://{webhook_host}:{webhook_port}{webhook_path}"
        log.info(f"Registering webhook for {url}")
        await bot.set_webhook(
            url=url,
            certificate=webhook_certificate,
        )

    async def on_shutdown(dp):
        # Remove webhook.
        await bot.delete_webhook()

        # Close Redis connection.
        await dp.storage.close()
        await dp.storage.wait_closed()

    log.info("Starting webhook")
    aiogram.utils.executor.start_webhook(
        dispatcher=dp,
        webhook_path=webhook_path,
        on_startup=on_startup,
        on_shutdown=on_shutdown,
        skip_updates=True,
        ssl_context=ssl_context,
        port=webhook_port,
    )

def main(argv):
    # Parse CLI arguments
    parser = argparse.ArgumentParser(description="Run RCV Bot server")
    parser.add_argument("-c", "--config", default="config.ini", help="Configuration file path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Use DEBUG logging")
    args = parser.parse_args(argv)

    # Set log level
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO
    )

    # Load configuration
    config = configparser.ConfigParser()
    config.read(args.config)

    def register(dp):
        dp.register_message_handler(send_welcome, commands=['start', 'help'])
        dp.register_message_handler(echo)

    log.info("Setting up webhook bot")
    webhook_bot(
        config=config,
        register_callback=register,
    )

if __name__ == "__main__":
    main(sys.argv[1:])
