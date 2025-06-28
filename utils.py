from datetime import time, timedelta, datetime
import json
import logging
import pytz
from config import Strategy
from constants import INDEXS

logger = logging.getLogger(__name__)

def get_time_frame_stamps(interval: int) -> list[time]:
    market_start = datetime.strptime("09:00:00", "%H:%M:%S")
    market_end = datetime.strptime("15:30:00", "%H:%M:%S")
    now = datetime.now(pytz.timezone("Asia/Kolkata")).replace(second=0, microsecond=0)

    timestamps = []
    current_time = market_start + timedelta(minutes=interval)

    while current_time <= market_end:
        if current_time.time() >= now.time():
            timestamps.append(current_time.time().replace(second=0, microsecond=0))
        current_time += timedelta(minutes=interval)

    return timestamps


def get_alloted_fund(underlying: str, strategy: Strategy):
    return strategy.fund_allocations[INDEXS[underlying].lower()]


def is_sq_off():
    with open("config.json", "r") as file:
        config_json = json.load(file)
    if config_json["sqaure_off_all"].lower() == "true":
        config_json["sqaure_off_all"] = "false"
        with open("config.json", "w") as f:
            json.dump(config_json, f, indent=4)
        return True
    return False


def calculate_pnl(strategy: Strategy):
    pnl = 0
    for archived_position in strategy.archived_positons:
        if archived_position.net_sell_quantity <= archived_position.net_buy_quantity:
            realized_pnl = archived_position.net_sell_quantity * (
                archived_position.sell_average_price
                - archived_position.buy_average_price
            )
            pnl += realized_pnl
        logger.debug(f"net_sell_quantity: {archived_position.net_sell_quantity}, net_buy_quantity: {archived_position.net_buy_quantity}, sell_average_price: {archived_position.sell_average_price}, buy_average_price: {archived_position.buy_average_price}")
    return round(pnl, 4)
