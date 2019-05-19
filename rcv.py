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
import typing

# https://pypi.org/project/aiogram/
import aiogram
import aiogram.contrib.fsm_storage.redis
import aiogram.dispatcher
import aiogram.dispatcher.filters.state
import aiogram.utils.executor
import aiogram.utils.markdown as md

# https://pypi.org/project/cryptography/
import cryptography
import cryptography.x509.oid
import cryptography.hazmat.backends
import cryptography.hazmat.primitives
import cryptography.hazmat.primitives.asymmetric

log = logging.getLogger("rcv")

#
# Visualization
#

async def _result_diagram(ballots):
    # TODO https://plot.ly/python/sankey-diagram/
    # TODO http://www.mikerobe007.ca/2018/10/london-instant-runoff-breakdown.html
    pass

async def result_diagram(ballots):
    # Use a task since this could be an expensive operation
    task = asyncio.create_task(_result_diagram(ballots))
    await task

#
# State
#

class CreatePoll(aiogram.dispatcher.filters.state.StatesGroup):
    end_date = aiogram.dispatcher.filters.state.State()
    options = aiogram.dispatcher.filters.state.State()

#
# Handlers
#

def register(dp):
    # TODO: can use `await dp.storage.redis()` to get a plain redis connection outside the FSM?

    @dp.message_handler(commands=["start", "help"])
    async def send_welcome(message: aiogram.types.Message):
        await dp.bot.send_message(
            message.chat.id,
            """Hi, I'm RankedPollBot!

I create polls where you can rank each option instead of just choosing one. This is called Ranked Choice Voting or Instant Runoff. Since voters don't need to guess how everyone else will vote, it captures the voters' preference more accurately than a conventional First Past the Post poll.

Use /newpoll to create a poll
Use /polls to show your polls""",
        )


    @dp.message_handler(
        state="*",
        commands=["cancel"],
    )
    async def cancel_handler(
        message: aiogram.types.Message,
        state: aiogram.dispatcher.FSMContext,
    ):
        await state.finish()
        await dp.bot.send_message(
            message.chat.id,
            "Cancelled.",
            reply_markup=aiogram.types.ReplyKeyboardRemove(),
        )


    @dp.message_handler(commands=["newpoll"])
    async def new_poll(message: aiogram.types.Message):
        await CreatePoll.end_date.set()

        markup = aiogram.types.ReplyKeyboardMarkup(
            resize_keyboard=True,
            selective=True
        )
        markup.add("1", "3", "7")
        markup.add("14", "30")

        await dp.bot.send_message(
            message.chat.id,
            "How many days do you want your poll to run for?",
            reply_markup=markup,
        )


    @dp.message_handler(
        lambda message: not message.text.isdigit(),
        state=CreatePoll.end_date
    )
    async def date_not_digit(message: aiogram.types.Message):
        await dp.bot.send_message(
            message.chat.id,
            "How many days? (digits only)",
        )


    @dp.message_handler(
        lambda message: not 1 <= int(message.text) <= 30,
        state=CreatePoll.end_date
    )
    async def date_not_in_range(message: aiogram.types.Message):
        await dp.bot.send_message(
            message.chat.id,
            "How many days? (must be between 1 and 30)"
        )


    @dp.message_handler(state=CreatePoll.end_date)
    async def process_age(
        message: aiogram.types.Message,
        state: aiogram.dispatcher.FSMContext
    ):
        await CreatePoll.options.set()
        days = int(message.text)
        async with state.proxy() as data:
            data["days"] = days
            data["options"] = []

        await dp.bot.send_message(
            message.chat.id,
            f"""Ok, your poll will run for {days} days after you first share it. Now, let's fill out the options. Send each option, one at a time. You can also:

Use /done to finish
Use /delete to remove the last entered option
Use /cancel to abort creating this poll""",
            reply_markup=aiogram.types.ReplyKeyboardRemove(),
        )


    @dp.message_handler(
        lambda message: not 1 <= len(message.text) <= 100,
        state=CreatePoll.options
    )
    async def option_wrong_length(message: aiogram.types.Message):
        await dp.bot.send_message(
            message.chat.id,
            "Option is too long, try again. (100 characters max)",
        )


    @dp.message_handler(
        commands=["done"],
        state=CreatePoll.options
    )
    async def option_done(
        message: aiogram.types.Message,
        state: aiogram.dispatcher.FSMContext
    ):
        async with state.proxy() as data:
            if len(data["options"]) > 0:
                # TODO store poll in long-term database
                # TODO assign poll ID via redis LPUSH
                poll_id = 1

                markup = aiogram.types.InlineKeyboardMarkup()
                markup.add(aiogram.types.InlineKeyboardButton(
                    text="Start Poll",
                    switch_inline_query=f"startpoll {poll_id}",
                ))

                formatted_options = "\n".join(sorted(data["options"]))
                await dp.bot.send_message(
                    message.chat.id,
                    f"""Ok, your poll #{poll_id} is ready. The options are:

{formatted_options}

When you want to share it, click the start button here""",
                    reply_markup=markup,
                )
                await state.finish()
            else:
                await dp.bot.send_message(
                    message.chat.id,
                    "Your poll doesn't have any options, add some before using /done"
                )



    @dp.message_handler(
        commands=["delete"],
        state=CreatePoll.options
    )
    async def option_delete(
        message: aiogram.types.Message,
        state: aiogram.dispatcher.FSMContext
    ):
        opt = None
        try:
            async with state.proxy() as data:
                opt = data["options"].pop()
        except IndexError:
            pass
        if opt:
            await dp.bot.send_message(
                message.chat.id,
                f"Ok, last option was deleted: {opt}",
            )
        else:
            await dp.bot.send_message(
                message.chat.id,
                f"No options exist to delete",
            )


    @dp.message_handler(state=CreatePoll.options)
    async def option_new(
        message: aiogram.types.Message,
        state: aiogram.dispatcher.FSMContext
    ):
        option = message.text
        async with state.proxy() as data:
            data["options"].append(option)

        await dp.bot.send_message(
            message.chat.id,
            "Ok, next option?",
        )


    @dp.callback_query_handler(lambda callback_query: True)
    async def poll_vote(callback_query: aiogram.types.CallbackQuery):
        await callback_query.answer()


    @dp.message_handler()
    async def catchall(message: aiogram.types.Message):
        await dp.bot.send_message(
            message.chat.id,
            f"Sorry, I don't know how to handle your message. Try /help or /cancel",
        )

#
# Main
#

def webhook_bot(config, register_callback, loop=None):
    log.info("Applying configuration")
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

    log.info("Registering handlers")
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

    log.info("Defining startup and shutdown actions")

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

    log.info("Setting up webhook bot")
    webhook_bot(
        config=config,
        register_callback=register,
    )

if __name__ == "__main__":
    main(sys.argv[1:])
