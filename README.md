# q-countdown-timer

## What is it?

A countdown timer with ability to add a pin-encrypted message.

## Installation

You need to install cryptography for python:

```bash
pip install cryptography
```

## Usage

Run the custozime.py script.

```bash
python3 custozime.py
```

It will ask you for:

- timestamp, from which the countdown timer should count
- the path to the file in which you will contain the content of the message to be displayed on the page. the contents of the file will appear in the div "card" when you enter the pin appropriately. so you should treat it as an html file, you can for example add style attribute for css.
- pin, with which the message will be secured and encrypted.

For the web, host only the "frontend" directory. Any reasonable web server should be fine. Remember to use https if you want to benefit from PWA.
