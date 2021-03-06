# Telegram Ranked Poll Bot

## Overview

This the source code of [@RankedPollBot](https://t.me/RankedPollBot); a poll bot for the [Telegram](https://telegram.org/) messaging service. It's written in Python 3, and is ASL v2 licensed.

Ranked Poll Bot provides polls where you can rank each option instead of just choosing one. This is called Ranked Choice Voting or [Instant Runoff](https://en.wikipedia.org/wiki/Instant-runoff_voting). Since voters don't need to guess how everyone else will vote, it captures the voters' preference more accurately than a conventional [First Past the Post](https://en.wikipedia.org/wiki/First-past-the-post_voting) poll.

## Usage

There's probably no need for you to deploy this server yourself. To use the bot, just [talk to it on Telegram](https://t.me/RankedPollBot).

## Install

```bash
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="149.154.160.0/20" port protocol="tcp" port="8443" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="91.108.4.0/22" port protocol="tcp" port="8443" accept'
firewall-cmd --reload
dnf install redis npm ImageMagick google-noto-emoji-color-fonts python3-pyyaml
systemctl enable redis
systemctl start redis
useradd rcv
su - rcv
pip3 install --user aiogram aioredis cryptography
echo "prefix=${HOME}/.local" >> ~/.npmrc
npm install -g svg-sankey
git clone https://github.com/ASzc/telegram-rcv-bot.git
cd telegram-rcv-bot
vim config.ini
exit
curl -Lo /usr/lib/systemd/system/rcv.service https://raw.githubusercontent.com/ASzc/dawbrn/master/rcv.service
systemctl enable rcv
systemctl start rcv
```
