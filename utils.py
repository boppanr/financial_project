from datetime import time, timedelta, datetime

import pytz

from config import Strategy
from constants import INDEXS

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
