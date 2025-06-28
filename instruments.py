import pandas as pd
import requests
from typing import Dict, List
from datetime import datetime
from dateutil.relativedelta import relativedelta
from enums import ApiProvider, ExpiryType
from constants import AVAILABLE_BROKERS, INDICES, LOT_SIZE

expiry_map = {ExpiryType.WEEKLY.name: {}, ExpiryType.MONTHLY.name: {}}
instruments_map = {broker: {} for broker in AVAILABLE_BROKERS}
fyers_instruments_map = {}
groww_instruments_map = {}
gopocket_instruments_map = {}

BASE_URL = "https://api.kite.trade"


class Instrument:
    def __init__(
        self, exchange: str, instrument_id: str, instrument_type, trading_symbol: str
    ):
        self.exchange = exchange
        self.instrument_id = instrument_id
        self.instrument_type = instrument_type
        self.trading_symbol = trading_symbol

underlying_instruments: Dict[str, Instrument] = {}
instruments: Dict[str, Dict]  = {}
instruments_by_trading_symbol: Dict[str, Dict]  = {}

def generate_trading_symbol(
    exchange: str,
    underlying: str,
    instrument_type: str,
    expiry_date: datetime,
    strike_price: float,
    option_type: str,
):
    return "-".join(
        [
            exchange,
            underlying,
            instrument_type,
            expiry_date.strftime("%y%m%d"),
            "{:.1f}".format(strike_price),
            option_type,
        ]
    )


def download_master_data():
    url = BASE_URL + "/instruments"
    response = requests.get(url, timeout=20)
    response.raise_for_status()
    return response.text


def filter_master_data_by_index(
    master_data: dict, exchange: str, fno_name: str, underlying: str
):
    parsed_data = {}
    master_data["tradingsymbol"] = master_data["tradingsymbol"].str.replace('"', '', regex=False)
    fno_data = master_data[
        (master_data["exchange"] == exchange) & (master_data["name"] == fno_name)
    ].copy()

    fno_data.loc[:, "expiry_int"] = (
        fno_data["expiry"].str.replace("-", "").astype(int) - 20000000
    )
    opt_expiries = fno_data[fno_data["segment"] == f"{exchange}-OPT"][
        "expiry_int"
    ].unique()
    fut_expiries = fno_data[fno_data["segment"] == f"{exchange}-FUT"][
        "expiry_int"
    ].unique()
    opt_expiries.sort()
    fut_expiries.sort()

    fno_data["expiry"] = pd.to_datetime(fno_data["expiry"], format="%Y-%m-%d")
    weekly_expiry = int(opt_expiries[0])
    next_weekly_expiry = int(opt_expiries[1])
    monthly_expiry = int(fut_expiries[0])
    if exchange == "BFO":
        ## getting monthly expiry for BSE indexes
        today = datetime.now().date()
        weekly_expiry_date = datetime.strptime(str(weekly_expiry), "%y%m%d").date()
        if today.month != weekly_expiry_date.month:
            today += relativedelta(months=1)
        current_month_expiry = fno_data[(fno_data["expiry"].dt.month == today.month) & (fno_data["expiry"].dt.year == today.year)]
        monthly_expiry = int(current_month_expiry["expiry"].max().strftime('%y%m%d'))

    und_name = underlying
    if underlying == "NIFTY":
        und_name = "NIFTY 50"
    elif underlying == "BANKNIFTY":
        und_name = "NIFTY BANK"
    elif underlying == "FINNIFTY":
        und_name = "NIFTY FIN SERVICE"
    elif underlying == "MIDCPNIFTY":
        und_name = "NIFTY MID SELECT"
    elif underlying == "SENSEX50":
        und_name = "SENSEX"

    cash_instrument = master_data[
        (master_data["tradingsymbol"] == und_name)
        & (master_data["segment"] == "INDICES")
    ].iloc[0]

    underlying_instruments[cash_instrument["instrument_token"]] = Instrument(
        cash_instrument["exchange_token"],
        cash_instrument["instrument_token"],
        "INDICES",
        und_name
    )

    expiry_map[ExpiryType.WEEKLY.name][underlying] = datetime.strptime(str(weekly_expiry), "%y%m%d").date()
    expiry_map[ExpiryType.MONTHLY.name][underlying] = datetime.strptime(str(monthly_expiry), "%y%m%d").date()

    opt_data = fno_data[
        (fno_data["segment"] == f"{exchange}-OPT")
        & (fno_data["expiry_int"].isin([weekly_expiry, next_weekly_expiry, monthly_expiry]))
    ]

    lot_size = opt_data["lot_size"].unique()[0]
    LOT_SIZE[underlying] = int(lot_size)

    for _, row in opt_data.iterrows():
        system_trading_symbol = generate_trading_symbol(
            row["exchange"],
            row["name"],
            "OPTIDX",
            row["expiry"],
            row["strike"],
            row["instrument_type"],
        )
        instrument = {
            "token": str(row["exchange_token"]),
            "pricefeed_token": str(row["instrument_token"]),
            "exchange": row["exchange"],
            "underlying": row["name"],
            "instrument_type": "OPTIDX",
            "expiry_date": row["expiry"].strftime("%y%m%d"),
            "strike_price": row["strike"],
            "option_type": row["instrument_type"],
            "trading_symbol": row["tradingsymbol"],
            "lot_size": lot_size,
        }
        parsed_data[instrument["pricefeed_token"]] = instrument
        parsed_data[system_trading_symbol] = instrument
        instruments_by_trading_symbol[system_trading_symbol] = instrument
        instruments[instrument["pricefeed_token"]] = instrument
    system_trading_symbol = generate_trading_symbol(
            cash_instrument["exchange"],
            cash_instrument["name"],
            "OPTIDX",
            datetime(1970, 1, 1),
            cash_instrument["strike"],
            cash_instrument["instrument_type"],
        )
    instrument = {
        "token": str(cash_instrument["exchange_token"]),
        "pricefeed_token": str(cash_instrument["instrument_token"]),
        "exchange": cash_instrument["exchange"],
        "underlying": cash_instrument["name"],
        "instrument_type": "OPTIDX",
        "expiry_date": datetime(1970, 1, 1).strftime("%y%m%d"),
        "strike_price": cash_instrument["strike"],
        "option_type": cash_instrument["instrument_type"],
        "trading_symbol": cash_instrument["tradingsymbol"],
        "lot_size": lot_size,
    }
    parsed_data[instrument["pricefeed_token"]] = instrument
    parsed_data[system_trading_symbol] = instrument
    instruments_by_trading_symbol[system_trading_symbol] = instrument
    instruments[instrument["pricefeed_token"]] = instrument

    return parsed_data


def load_instruments_from_kite():
    master_data = pd.read_csv("https://api.kite.trade/instruments")

    all_instruments: Dict[str, Instrument] = {}
    for index, index_info in INDICES.items():
        instruments = filter_master_data_by_index(
            master_data=master_data,
            exchange=index_info[0],
            fno_name=index_info[1],
            underlying=index,
        )
        all_instruments.update(instruments)
    return all_instruments


def load_instruments():
    parsed_master_data = load_instruments_from_kite()
    map_instruments(parsed_master_data)
    load_fyers_instruments()
    load_groww_instruments()
    load_gopocket_instruments()


def map_instruments(parsed_master_data: Dict[str, Instrument]):
    for _, instrument_dict in parsed_master_data.items():
        for broker in AVAILABLE_BROKERS:
            if broker == ApiProvider.ZERODHA.name:
                instruments_map[broker][instrument_dict["pricefeed_token"]] = (
                    Instrument(
                        instrument_dict["exchange"],
                        instrument_dict["token"],
                        instrument_dict["instrument_type"],
                        instrument_dict["trading_symbol"],
                    )
                )
            elif broker == ApiProvider.FYERS.name:
                exchange = {"NSE": "NSE", "BSE": "BSE", "NFO": "NSE", "BFO": "BSE"}[
                    instrument_dict["exchange"]
                ]
                instrument_id = f"{exchange}:{instrument_dict["trading_symbol"]}"
                instruments_map[broker][instrument_dict["pricefeed_token"]] = (
                    Instrument(
                        exchange, instrument_id, instrument_dict["instrument_type"], instrument_dict["trading_symbol"]
                    )
                )
            elif broker == ApiProvider.GROWW.name:
                exchange = {"NSE": "NSE", "BSE": "BSE", "NFO": "NSE", "BFO": "BSE"}[
                    instrument_dict["exchange"]
                ]
                expiry_str = instrument_dict["expiry_date"]
                formatted_expiry = expiry_str[:2] + expiry_str[2:4] + expiry_str[4:]
                trading_symbol = f"{instrument_dict["underlying"]}{formatted_expiry}{strike_part}{instrument_dict["option_type"]}"
                segment = {
                    "NFO-OPT": "FNO",
                    "BFO-OPT": "FNO",
                    "NFO-FUT": "FNO",
                    "BFO-FUT": "FNO",
                    "CASH": "CASH",
                    "INDEX": "CASH",
                    "FUTIDX": "FNO",
                    "OPTIDX": "FNO"
                }[instrument_dict["instrument_type"]]
                instruments_map[broker][instrument_dict["pricefeed_token"]] = (
                    Instrument(
                        exchange, instrument_dict["token"], segment, trading_symbol
                    )
                )
            elif broker == ApiProvider.SHOONYA.name:
                exchange = {"NSE": "NSE", "BSE": "BSE", "NFO": "NSE", "BFO": "BSE"}[
                    instrument_dict["exchange"]
                ]
                contract_type = {"FUT": "F", "CE": "C", "PE": "P", "EQ": "EQ"}[
                    instrument_dict["option_type"]
                ]
                expiry_str = instrument_dict["expiry_date"]
                formatted_expiry = expiry_str[:2] + expiry_str[2:4] + expiry_str[4:]
                strike_part = (
                    str(instrument_dict["strike_price"])
                    if instrument_dict["strike_price"] > 0
                    else ""
                )
                trading_symbol = f"{instrument_dict["underlying"]}{formatted_expiry}{contract_type}{strike_part}"
                instruments_map[broker][instrument_dict["pricefeed_token"]] = (
                    Instrument(
                        exchange,
                        instrument_dict["token"],
                        instrument_dict["instrument_type"],
                        trading_symbol,
                    )
                )


def get_instrument(broker_name: str, zerodha_instrument_id: str) -> Instrument:
    return instruments_map[broker_name][zerodha_instrument_id]


def get_instruent_token_from_name(name: str) -> Instrument:
    return str(instruments_by_trading_symbol[name]["pricefeed_token"])


def get_exchnage_token(instrument_token: str) -> str:
    return str(instruments[instrument_token]["token"])


def get_zerodha_tradingsymbol(instrument_token: str) -> str:
    return str(instruments[instrument_token]["trading_symbol"])


def get_expiry(underlying: str, type: str):
    return expiry_map[type][underlying]


def load_fyers_instruments():
    ##NSE
    url1 = "https://public.fyers.in/sym_details/NSE_FO_sym_master.json"
    response1 = requests.get(url1, timeout=20)
    response1.raise_for_status()
    data1 = response1.json()
    for trading_symbol1, instrument_info1 in data1.items():
        fyers_instruments_map[str(instrument_info1["exToken"])] = trading_symbol1
    ##BSE
    url2 = "https://public.fyers.in/sym_details/BSE_FO_sym_master.json"
    response2 = requests.get(url2, timeout=20)
    response2.raise_for_status()
    data2 = response2.json()
    for trading_symbol2, instrument_info2 in data2.items():
        fyers_instruments_map[str(instrument_info2["exToken"])] = trading_symbol2


def get_fyers_tradingsymbol(instrument_token: str) -> str:
    exchange_token = get_exchnage_token(instrument_token)
    return fyers_instruments_map[exchange_token]


def load_groww_instruments():
    url = "https://growwapi-assets.groww.in/instruments/instrument.csv"
    resp = requests.get(url=url)
    raw_data = resp.text.split("\n")
    raw_data.pop(0)
    for data in raw_data:
        instrument_data = data.split(",")
        if instrument_data == ['']:
            continue
        groww_instruments_map[instrument_data[1]] = instrument_data[2]


def get_groww_tradingsymbol(instrument_token: str) -> str:
    exchange_token = get_exchnage_token(instrument_token)
    return groww_instruments_map[exchange_token]


def load_gopocket_instruments():
    nfo_url = "https://web.gopocket.in/contract/csv/nfo"
    bfo_url = "https://web.gopocket.in/contract/csv/bfo"
    nfo_df = pd.read_csv(nfo_url)
    bfo_df = pd.read_csv(bfo_url)
    main_df = pd.concat([nfo_df, bfo_df])
    main_df = main_df.dropna(subset=["Token"])
    for _, data in main_df.iterrows():
        gopocket_instruments_map[str(int(data["Token"]))] = data["Trading Symbol"]


def get_gopocket_tradingsymbol(instrument_token: str) -> str:
    exchange_token = get_exchnage_token(instrument_token)
    return gopocket_instruments_map[exchange_token]