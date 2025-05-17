from datetime import datetime, time
import os
import json
import logging
from typing import List
from enums import ApiProvider, StrategyStatus
from models import Position

logger = logging.getLogger(__name__)


class Api:
    def __init__(self, api_config_json: dict):
        self.provider = ApiProvider(api_config_json["provider"].upper())
        self.creds = api_config_json["creds"]


class Strategy:
    def __init__(self, strategy_json: dict):
        self.check_candle = strategy_json["check_candle"]
        self.fund_allocations = strategy_json["fund_allocations"]
        self.stop_loss = strategy_json["stop_loss"]
        self.profit_target = strategy_json["profit_target"]
        self.trailings = strategy_json["trailings"]
        self.buffer_price = strategy_json["buffer_price_percentage"]
        self.strike_buffer_precentage = strategy_json["strike_buffer_precentage"]
        end_time_parts = strategy_json["strategy_end_time"].split(":")
        self.strategy_end_time = time(int(end_time_parts[0]), int(end_time_parts[1]), int(end_time_parts[2]))

        self.running_positions: List[Position] = []
        self.archived_positons: List[Position] = []

        self.status = StrategyStatus.CREATED


class Config:
    if not os.environ.get("LINUX"):
        if not os.path.exists("config.json"):
            logger.error("config.json dosn't exist")
            exit()
        config_json = json.load(open("config.json"))
        PRICEFEED_CREDS = config_json["pricefeed_creds"]
        API = Api(config_json["api"])
        STRATEGY = Strategy(config_json["strategy"])
        PRICEFEED_ACCESS_TOKEN = ""
    else:
        BROKER = os.environ.get("BROKER")
        BROKER_CREDS = json.loads(os.environ.get("BROKER_CREDS"))
