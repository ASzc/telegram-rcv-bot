#!/usr/bin/env python3

import argparse
import asyncio
import base64
import configparser
import datetime
import hashlib
import io
import json
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
import aiogram.contrib.middlewares.logging
import aiogram.dispatcher
import aiogram.dispatcher.filters.state
import aiogram.utils.exceptions
import aiogram.utils.executor
import aiogram.utils.markdown as md

# https://pypi.org/project/cryptography/
import cryptography
import cryptography.x509.oid
import cryptography.hazmat.backends
import cryptography.hazmat.primitives
import cryptography.hazmat.primitives.asymmetric

# https://pypi.org/project/PyYAML/
import yaml

log = logging.getLogger("rcv")

#
# Visualization
#

async def result_diagram(options, raw_ballots):
    # Calculate votes in each stage:
    #   - narrow by eliminating the least popular option.
    #   - stop when one candidate is left.
    #   - use virtual Exhausted column for ballots that stop short of ranking
    #     all options.

    # Pre-split ballots
    ballots = []
    for ballot in raw_ballots.values():
        ballot = ballot.split(",")
        if ballot == [""]:
            ballot = []
        ballots.append([int(b) for b in ballot])

    # Count total votes in each stage, determine who is elminated
    exhausted = "exhausted"
    paths = {}
    stages = []
    eliminated = set()
    eliminated_nodes = set()
    active = set()
    for b in ballots:
        if len(b) > 0:
            active.add(b[0])
    stage_index = 0
    while len(active) > 1:
        stage = {a: 0 for a in active}
        stage[exhausted] = 0
        stages.append(stage)

        for ballot in ballots:
            for choice in ballot:
                if choice in active:
                    break
            else:
                choice = exhausted
            stage[choice] += 1

        print(f"Stage: {stage}")

        # Eliminate the least popular option
        # If tie for lowest, eliminate all the lowest together
        options_by_score = {}
        for option, score in stage.items():
            if option == exhausted:
                continue
            if score not in options_by_score:
                options_by_score[score] = set()
            options_by_score[score].add(option)
        lowest_score = min(options_by_score.keys())
        #print(f"OBS:       {options_by_score}")
        #print(f"Low:       {lowest_score}")
        print(f"Eliminate: {options_by_score[lowest_score]}")
        eliminated.update(options_by_score[lowest_score])

        for ballot in ballots:
            try:
                primary_choice = ballot[0]
            except IndexError:
                primary_choice = exhausted

            ballot_iter = iter(ballot)
            for choice in ballot_iter:
                if choice in active:
                    break
            else:
                choice = exhausted

            if choice not in eliminated or choice == exhausted:
                # The ballots that chose an option that wasn't eliminated will
                # always go to the same choice in the next stage.
                next_choice = choice
            else:
                # The ballots that chose an option that was eliminated will go
                # to their next best choice in the next stage, assuming it
                # hasn't been removed already.
                for next_choice in ballot_iter:
                    if next_choice in active and next_choice not in eliminated:
                        break
                else:
                    next_choice = exhausted

            k_from = f"{stage_index}-{choice}"
            k_to = f"{stage_index+1}-{next_choice}"

            if k_from not in paths:
                paths[k_from] = {}
            if k_to not in paths[k_from]:
                paths[k_from][k_to] = {}
            if primary_choice not in paths[k_from][k_to]:
                paths[k_from][k_to][primary_choice] = 0
            paths[k_from][k_to][primary_choice] += 1

        for e in eliminated:
            eliminated_nodes.add(f"{stage_index}-{e}")
            active.discard(e)
        stage_index += 1

    winner = options[active.pop()] if len(active) > 0 else "Tied (no winner)"

    # Convert stages into D3 Sanke data
    node_dedup = set()
    for node, dests in paths.items():
        node_dedup.add(node)
        node_dedup.update(dests.keys())
    nodes = []
    for node in sorted(node_dedup):
        index, option = node.split("-")
        title = "Exhausted" if option == exhausted else options[int(option)]
        if len(title) > 23:
            title = f"{title[:21]}..."
        if node in eliminated_nodes:
            title += " ❌"
        nodes.append({
            "id": node,
            "title": title,
        })

    links = []
    for k_from, dests in paths.items():
        for k_to, primary_choices in dests.items():
            for primary_choice, count in primary_choices.items():
                links.append({
                    "source": k_from,
                    "target": k_to,
                    "value": count,
                    "type": str(primary_choice),
                })

    chart = {
        "nodes": nodes,
        "links": links,
        "alignLinkTypes": True,
    }

    # Summary
    summary = yaml.dump(
        {
            "options": options,
            # Wipe out UIDs
            "ballots": sorted(raw_ballots.values()),
            "stages": stages,
            "chart": chart,
        },
        default_flow_style=False,
        encoding="utf-8",
        allow_unicode=True,
    )

    # Convert to SVG via layered D3 library
    with tempfile.TemporaryDirectory() as td:
        d3_json = os.path.join(td, "sanke.json")
        svg = os.path.join(td, "sanke.svg")
        png = os.path.join(td, "sanke.png")

        with open(d3_json, "w") as f:
            json.dump(chart, f, ensure_ascii=False)

        p = await asyncio.create_subprocess_shell(
            f"svg-sankey --size 1280,720 --margins 150,150 {d3_json} > {svg}",
        )
        await p.communicate()

        p = await asyncio.create_subprocess_exec(
            "convert",
            "-density", "200",
            svg,
            png,
        )
        await p.communicate()

        #p = await asyncio.create_subprocess_exec("cp", d3_json, "/tmp/a.json")
        #await p.communicate()
        #p = await asyncio.create_subprocess_exec("cp", svg, "/tmp/a.svg")
        #await p.communicate()
        #p = await asyncio.create_subprocess_exec("cp", png, "/tmp/a.png")
        #await p.communicate()

        p = await asyncio.create_subprocess_exec(
            "cat",
            png,
            stdout=asyncio.subprocess.PIPE,
        )
        sanke, stderr = await p.communicate()

        return (sanke, winner, summary)

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
            param = message.text.split(' ', 1)[1]
        except IndexError:
            await dp.bot.send_message(
                message.chat.id,
                """Hi, I'm RankedPollBot!

I create polls where you can rank each option instead of just choosing one. This is called Ranked Choice Voting or Instant Runoff. Since voters don't need to guess how everyone else will vote, it captures the voters' preference more accurately than a conventional First Past the Post poll.

Use /newpoll to create a poll
Use /polls to show your polls
Use /results <id> to show intermediate results for a poll
Use /stoppoll <id> to stop a poll and show the results""",
            )
        else:
            await vote_start(message, param)


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
                vote_code = base64.b32encode(os.urandom(15)).decode("ascii").lower()
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
                    f"""Poll: {title}

{formatted_options}

To vote, [follow this link](http://t.me/RankedPollBot?start={vote_code}) (stays within Telegram) and press **Start**.""",
                    parse_mode=aiogram.types.ParseMode.MARKDOWN,
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
    # List Polls
    #

    @dp.message_handler(commands=["polls"])
    async def list_poll(message: aiogram.types.Message):
        redis = await dp.storage.redis()
        vote_codes = await redis.lrange(f"user_{message.from_user.id}", 0, -1)
        reply = "Active polls:"
        none = True
        for i, vote_code in enumerate(vote_codes):
            none = False
            title = await redis.get(f"title_{vote_code}")
            reply += f"\n{i+1}. {title}"
        if none:
            reply += "\nNo polls active"
        await dp.bot.send_message(
            message.chat.id,
            reply,
        )

    #
    # Stop Poll
    #

    @dp.message_handler(commands=["results"])
    async def results(message: aiogram.types.Message):
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
                await results_message(vote_code, message)

    async def results_message(vote_code, message, intermediate=True):
        redis = await dp.storage.redis()
        title = await redis.get(f"title_{vote_code}")
        options = await redis.lrange(f"options_{vote_code}", 0, -1)
        ballots = await redis.hgetall(f"ballots_{vote_code}")

        b, winner, summary = await result_diagram(options, ballots)
        bio = io.BytesIO(b)
        bio.name = "Vote Flow.png"

        desc = "Current Leader" if intermediate else "Winner"

        vote_link = f"\n[You can vote here](http://t.me/RankedPollBot?start={vote_code})\n" if intermediate else ""

        await dp.bot.send_document(
            message.chat.id,
            bio,
            caption=f"""{title}

{desc}: **{winner}**
{vote_link}
Need help?
[Alternative Vote Explained](https://youtu.be/3Y3jE3B8HsE?t=104)
[Instant Runoff](https://en.wikipedia.org/wiki/Instant-runoff_voting#Election_procedure)
[STV Election Example](https://youtu.be/Ac9070OIMUg?t=13)
[Sankey Diagrams](https://en.wikipedia.org/wiki/Sankey_diagram)""",
            parse_mode=aiogram.types.ParseMode.MARKDOWN,
        )

        bio = io.BytesIO(summary)
        bio.name = "Poll Data.yaml"
        await dp.bot.send_document(
            message.chat.id,
            bio,
            caption=f"Poll data summary: {title}"
        )


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
                await dp.bot.send_message(
                    message.chat.id,
                    f"Poll {poll_id} stopped. Forward the following results to those you want to share it with.",
                )
                await results_message(vote_code, message, intermediate=False)
                await redis.lrem(f"user_{message.from_user.id}", -1, vote_code)
                await redis.delete(
                    *(f"k_{vote_code}" for k in ("createtime", "title", "options"))
                )


    #
    # Vote in Poll
    #

    def vote_text(title, selected=[], finished=False):
        if selected:
            formatted_options = "\n".join(f"{i+1}. {o}" for i, o in enumerate(selected))
            t = f"""{title}

{formatted_options}"""
            if finished:
                t += """

Finished! Thanks for voting."""
            else:
                t += """

Select your next best preference. If you need to start over, select Reset. When you're done ranking the options, press Finish.

Your rankings can't be changed after pressing Finish!"""
            return t
        else:
            return f"""You're voting in a poll:
{title}

Select the options below in your order of preference. The first option you pick is what you like the most. If you need to start over, select Reset. If you want to stop before ranking all the options, press Finish.

Your rankings can't be changed after pressing Finish!"""


    def vote_markup(vote_code, options, selected=[]):
        # Hide options that have been selected, but keep the overall index
        # value constant.
        selected = set([int(s) for s in selected])
        shadowed_options = []
        for i, o in enumerate(options):
            if i not in selected:
                shadowed_options.append((i, o))
        random.shuffle(shadowed_options)

        markup = aiogram.types.InlineKeyboardMarkup()
        for i, option in shadowed_options:
            markup.add(aiogram.types.InlineKeyboardButton(
                text=option,
                callback_data=f"{i}.{vote_code}",
            ))
        markup.add(
            aiogram.types.InlineKeyboardButton(
                text="Reset",
                callback_data=f"reset.{vote_code}",
            ),
            aiogram.types.InlineKeyboardButton(
                text="Finish",
                callback_data=f"finish.{vote_code}",
            ),
        )
        return markup


    async def vote_start(message: aiogram.types.Message, vote_code):
        redis = await dp.storage.redis()

        # Disallow re-start on an active or finished voting session
        uid = str(message.from_user.id)
        user_ballot = await redis.hget(f"ballots_{vote_code}", uid)
        if user_ballot:
            await dp.bot.send_message(
                message.chat.id,
                "You've already voted in this poll",
            )
            return

        title = await redis.get(f"title_{vote_code}")
        if title is not None:
            title = title
            options = await redis.lrange(f"options_{vote_code}", 0, -1)
            await dp.bot.send_message(
                message.chat.id,
                vote_text(title),
                reply_markup=vote_markup(vote_code, options),
            )
        else:
            await dp.bot.send_message(
                message.chat.id,
                "The poll you want to vote in does not exist, maybe it ended? To make your own poll, try /help",
            )


    @dp.callback_query_handler(lambda callback_query: True)
    async def poll_vote(callback_query: aiogram.types.CallbackQuery):
        try:
            await callback_query.answer()
        except aiogram.utils.exceptions.BadRequest:
            return

        uid = str(callback_query.from_user.id)
        index_raw, vote_code = callback_query.data.split(".")

        redis = await dp.storage.redis()
        title = await redis.get(f"title_{vote_code}")
        options = await redis.lrange(f"options_{vote_code}", 0, -1)

        raw_selected = await redis.hget(f"ballots_{vote_code}", uid)
        if raw_selected:
            selected = raw_selected.split(",")
        else:
            selected = []

        message = callback_query.message
        if index_raw != "finish":
            if index_raw == "reset":
                selected = []
            else:
                index = int(index_raw)
                selected.append(str(index))

            await redis.hset(f"ballots_{vote_code}", uid, ",".join(selected))

            await message.edit_text(vote_text(title, [options[int(s)] for s in selected]))
            await message.edit_reply_markup(vote_markup(vote_code, options, selected))
        else:
            try:
                await message.edit_text(vote_text(title, [options[int(s)] for s in selected], True))
                await message.edit_reply_markup(aiogram.types.InlineKeyboardMarkup())
            except aiogram.utils.exceptions.MessageNotModified:
                pass


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

class ContextLogRecord(logging.LogRecord):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        task = asyncio.Task.current_task()
        if task is not None:
            if not hasattr(task, "uid"):
                h = hashlib.md5()
                h.update(str(id(task)).encode("ascii"))
                task.uid = base64.b32encode(h.digest()).decode("ascii")[:15].lower()
            self.log_context = task.uid
        else:
            self.log_context = "NoTask"

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
        base64.urlsafe_b64encode(os.urandom(21)).decode("ascii")
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
        encoding="utf-8",
        loop=loop,
    )
    dp = aiogram.dispatcher.Dispatcher(
        bot=bot,
        storage=storage,
        loop=loop,
    )

    dp.middleware.setup(aiogram.contrib.middlewares.logging.LoggingMiddleware("aiogram"))

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
        format="{log_context} {levelname}:{name}:{message}",
        style="{",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )
    logging.setLogRecordFactory(ContextLogRecord)

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
