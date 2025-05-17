from enums import ApiProvider

AVAILABLE_BROKERS = [provider.name for provider in ApiProvider]

STRIKE_DIFF = {
    "NIFTY": 50,
    "BANKNIFTY": 100,
    "FINNIFTY": 100,
    "MIDCPNIFTY": 50,
    "BANKEX": 100,
    "SENSEX": 100,
}

INDICES = {
    "NIFTY": ("NFO", "NIFTY"),
    "BANKNIFTY": ("NFO", "BANKNIFTY"),
    "FINNIFTY": ("NFO", "FINNIFTY"),
    "MIDCPNIFTY": ("NFO", "MIDCPNIFTY"),
    "SENSEX": ("BFO", "SENSEX"),
    "BANKEX": ("BFO", "BANKEX"),
}

INDEXS = {
    "NIFTY 50": "NIFTY",
    "NIFTY BANK": "BANKNIFTY",
    "NIFTY FIN SERVICE": "FINNIFTY",
    "NIFTY MID SELECT": "MIDCPNIFTY",
    "SENSEX": "SENSEX",
    "BANKEX": "BANKEX"
}

LOT_SIZE = {

}

FREEZE_QTY = {
    'NIFTY': {'WEEKLY': 24, 'NEXTWEEKLY': 24, 'MONTHLY': 24}, 
    'BANKNIFTY': {'WEEKLY': 20, 'NEXTWEEKLY': 20, 'MONTHLY': 20}, 
    'FINNIFTY': {'WEEKLY': 27, 'NEXTWEEKLY': 27, 'MONTHLY': 27}, 
    'MIDCPNIFTY': {'WEEKLY': 23, 'NEXTWEEKLY': 23, 'MONTHLY': 23}, 
    'SENSEX': {'WEEKLY': 25, 'NEXTWEEKLY': 25, 'MONTHLY': 25}, 
    'BANKEX': {'WEEKLY': 20, 'NEXTWEEKLY': 20, 'MONTHLY': 20}
}