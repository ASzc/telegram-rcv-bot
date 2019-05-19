#!/usr/bin/env python3

import argparse
import asyncio
import base64
import configparser
import datetime
import io
import logging
import os
import random
import ssl
import sys
import tempfile
import time
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
    title = aiogram.dispatcher.filters.state.State()
    options = aiogram.dispatcher.filters.state.State()

#
# Handlers
#

def register(dp):
    #
    # General
    #

    @dp.message_handler(commands=["start", "help"])
    async def send_welcome(message: aiogram.types.Message):
        try:
            param = int(message.text.split(' ', 1)[1])
        except IndexError:
            pass
        else:
            await vote_start(message, param)
        await dp.bot.send_message(
            message.chat.id,
            """Hi, I'm RankedPollBot!

I create polls where you can rank each option instead of just choosing one. This is called Ranked Choice Voting or Instant Runoff. Since voters don't need to guess how everyone else will vote, it captures the voters' preference more accurately than a conventional First Past the Post poll.

Use /newpoll to create a poll
Use /polls to show your polls
Use /stoppoll <id> to stop a poll and show the results""",
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

    #
    # Create Poll
    #

    @dp.message_handler(commands=["newpoll"])
    async def new_poll(message: aiogram.types.Message):
        await CreatePoll.title.set()

        await dp.bot.send_message(
            message.chat.id,
            "What's the question or title of the poll?",
        )

    @dp.message_handler(
        lambda message: not 1 <= len(message.text) <= 100,
        state=CreatePoll.title
    )
    async def title_wrong_length(message: aiogram.types.Message):
        await dp.bot.send_message(
            message.chat.id,
            "Title is too long, try again. (100 characters max)"
        )


    @dp.message_handler(state=CreatePoll.title)
    async def process_title(
        message: aiogram.types.Message,
        state: aiogram.dispatcher.FSMContext
    ):
        await CreatePoll.options.set()
        title = message.text
        async with state.proxy() as data:
            data["title"] = title
            data["options"] = []

        await dp.bot.send_message(
            message.chat.id,
            f"""Ok, now let's fill out the options. Send each option, one at a time. You can also:

Use /done to finish
Use /delete to remove the last entered option
Use /cancel to abort creating this poll""",
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
                title = data["title"]
                options = sorted(data["options"])
                formatted_options = "\n".join(f"- {o}" for o in options)
                vote_code = base64.b32encode(os.urandom(15)).decode('ascii').lower()
                await state.finish()

                redis = await dp.storage.redis()
                poll_id = await redis.rpush(f"user_{message.from_user.id}", vote_code)
                await redis.set(f"createtime_{vote_code}", int(time.time()))
                await redis.set(f"title_{vote_code}", title)
                await redis.rpush(f"options_{vote_code}", *options)

                await dp.bot.send_message(
                    message.chat.id,
                    f"""Ok, your poll #{poll_id} is ready. Forward the following message to those you want to share it with.""",
                )
                await dp.bot.send_message(
                    message.chat.id,
                    """Poll: {title}

    {formatted_options}

    To vote, follow this link and press Start:
    http://t.me/RankedPollBot?start={vote_code}""",
                )
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

    #
    # Stop Poll
    #

    @dp.message_handler(commands=["stoppoll"])
    async def stop_poll(message: aiogram.types.Message):
        try:
            poll_id = int(message.text.split(' ', 1)[1])
        except IndexError:
            await dp.bot.send_message(
                message.chat.id,
                "Specify a Poll ID number with the command. Try /polls to see which polls you have",
            )
        except ValueError:
            await dp.bot.send_message(
                message.chat.id,
                "Poll ID must be a number. Try /polls to see which polls you have",
            )
        else:
            redis = await dp.storage.redis()
            vote_code = await redis.lindex(f"user_{message.from_user.id}", poll_id - 1)
            if vote_code is None:
                await dp.bot.send_message(
                    message.chat.id,
                    "Poll ID does not exist. Try /polls to see which polls you have",
                )
            else:
                title = await redis.get(f"title_{vote_code}")
                options = await redis.lrange(f"options_{vote_code}", 0, -1)
                ballots = await redis.hgetall(f"ballots_{vote_code}")

                # TODO result_diagram
                await dp.bot.send_message(
                    message.chat.id,
                    "Poll {poll_id} stopped. Forward the following results to those you want to share it with.",
                )
                await dp.bot.send_message(
                    message.chat.id,
                    "TODO",
                )
                await redis.lrem(f"user_{message.from_user.id}", -1, vote_code)
                await redis.delete(
                    *(f"k_{vote_code}" for k in ("createtime", "title", "options"))
                )


    #
    # Vote in Poll
    #

    def vote_text(title, selected=[], finished=False):
        if selected:
            formatted_options = "\n".join(f"{i}. {o}" for i, o in enumerate(selected))
            t = f"""{title}

{formatted_options}"""
            if finished:
                t += """
Finished! Thanks for voting."""
            else:
                t += """
If you need to start over, select Reset. If you want to stop before ranking all the options, press Finish."""
            return t
        else:
            return f"""You're voting in a poll:
{title}

Select the options below in your order of preference. The first option you pick is the you like the most. If you need to start over, select Reset. If you want to stop before ranking all the options, press Finish.

Your rankings can't be changed after pressing Finish!"""


    def vote_markup(options, selected=[]):
        # Hide options that have been selected, but keep the overall index
        # value constant.
        selected = set([int(s) for s in selected])
        shadowed_options = []
        for i, o in enumerate(options):
            if i not in selected:
                shadowed_options.append((i, o))

        markup = aiogram.types.InlineKeyboardMarkup()
        for i, option in random.shuffle(shadowed_options):
            markup.add(aiogram.types.InlineKeyboardButton(
                text=option,
                callback_data=str(i),
            ))
        markup.add(
            aiogram.types.InlineKeyboardButton(
                text="Reset",
                callback_data="reset",
            ),
            aiogram.types.InlineKeyboardButton(
                text="Finish",
                callback_data="finish",
            ),
        )


    async def vote_start(message: aiogram.types.Message, vote_code):
        redis = await dp.storage.redis()
        title = await redis.get(f"title_{vote_code}")
        options = await redis.lrange(f"options_{vote_code}", 0, -1)
        if all(e != None for e in [title, options]):
            await dp.bot.send_message(
                message.chat.id,
                vote_text(title),
                reply_markup=vote_markup(options),
            )
        else:
            await dp.bot.send_message(
                message.chat.id,
                "The poll you want to vote in does not exist, maybe it ended? To make your own poll, try /help",
            )


    @dp.callback_query_handler(lambda callback_query: True)
    async def poll_vote(callback_query: aiogram.types.CallbackQuery):
        message = callback_query.message
        uid = str(message.from_user.id)
        index_raw, vote_code = callback_query.data.split(".")

        redis = await dp.storage.redis()
        title = await redis.get(f"title_{vote_code}")
        options = await redis.lrange(f"options_{vote_code}", 0, -1)

        if index_raw != "finish":
            if index_raw == "reset":
                selected = []
            else:
                index = int(index_raw)
                selected = (await redis.hget(f"ballots_{vote_code}", uid) or []).split(",")
                selected.append(str(index))
                await redis.hset(f"ballots_{vote_code}", uid, ",".join(selected))

            await message.edit_text(vote_text(title, selected))
            await message.edit_reply_markup(vote_markup(options, selected))
        else:
            await message.edit_text(vote_text(title, selected, True))
            await message.edit_reply_markup(aiogram.types.ReplyKeyboardRemove())

        await callback_query.answer()

    #
    # Catchall
    #

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
