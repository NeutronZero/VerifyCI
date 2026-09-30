"""Eight callers of send_email (blast exposure fixture)."""
from src.send import send_email


def notify_1():
    send_email("a")


def notify_2():
    send_email("b")


def notify_3():
    send_email("c")


def notify_4():
    send_email("d")


def notify_5():
    send_email("e")


def notify_6():
    send_email("f")


def notify_7():
    send_email("g")


def notify_8():
    send_email("h")
