# Telegram Ranked Poll Bot

## Overview

This the source code of [@RankedPollBot](https://t.me/RankedPollBot); a poll bot for the [Telegram](https://telegram.org/) messaging service. It's written in Python 3, and is ASL v2 licensed.

Ranked Poll Bot provides polls where you can rank each option instead of just choosing one. This is called Ranked Choice Voting or [Instant Runoff](https://en.wikipedia.org/wiki/Instant-runoff_voting). Since voters don't need to guess how everyone else will vote, it captures the voters' preference more accurately than a conventional [First Past the Post](https://en.wikipedia.org/wiki/First-past-the-post_voting) poll.

## Usage

There's probably no need for you to deploy this server yourself. To use the bot, just [talk to it on Telegram](https://t.me/RankedPollBot).

## Install

```bash
dnf install redis
systemctl enable redis
systemctl start redis
useradd rcv
su - rcv
pip3 install --user aiogram aioredis cryptography
./rcv.py
```
