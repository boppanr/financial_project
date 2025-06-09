import pandas as pd
from NorenRestApiPy.NorenApi import NorenApi
import pyotp
import logging
import uuid
import os
import time
from datetime import datetime, timedelta
import pytz
from openpyxl import load_workbook
import re
import xlwings as xw

# Configure logging to log into a file
log_file_path = os.path.join(os.path.dirname(__file__), 'log.txt')

class ShoonyaApiPy(NorenApi):
    def __init__(self):
        super().__init__(host='https://api.shoonya.com/NorenWClientTP/', websocket='wss://api.shoonya.com/NorenWSTP/')

def get_mac_address():
    """Return the MAC address of the current machine."""
    mac = uuid.getnode()
    return ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2)).lower()

def read_credentials_from_excel(file_path, sheet_name):
    """Read API credentials from an Excel file."""
    df = pd.read_excel(file_path, sheet_name=sheet_name, header=None)
    credentials = df.set_index(0).to_dict()[1]

    required_keys = ['user', 'pwd', 'token', 'vc', 'app_key','algotime','amt_midcpnifty','amt_finnifty','amt_banknifty','amt_sensex','amt_bankex','amt_nifty','amt_mcx']
    missing_keys = [key for key in required_keys if credentials.get(key) is None]
    if missing_keys:
        raise ValueError(f"Missing required credentials: {', '.join(missing_keys)}")

    return (credentials['user'], credentials['pwd'], credentials['token'], 
            credentials['vc'], credentials['app_key'],credentials['algotime'],credentials['amt_midcpnifty'],credentials['amt_finnifty'],credentials['amt_banknifty'],credentials['amt_sensex'],credentials['amt_bankex'],credentials['amt_nifty'],credentials['amt_mcx'])

def get_token_by_searchtext(api, exchange, searchtext):
    try:
        response = api.searchscrip(exchange=exchange, searchtext=searchtext)
        if response['stat'] == 'Ok' and 'values' in response:
            token = response['values'][0]['token']
            symbol = response['values'][0]['tsym']
            return token, symbol
        else:
            return None
    except Exception as e:
        return None

def get_last_38_minutes_high_low(api, exchange, token, algotime, interval='1m'):
    """Fetch high and low values for the last 38 minutes."""
    ist = pytz.timezone('Asia/Kolkata')
    end_time = datetime.now(ist).replace(second=0, microsecond=0)
    start_time = end_time - timedelta(minutes=algotime)

    start_time_unix = int(start_time.timestamp())
    end_time_unix = int(end_time.timestamp())

    try:
        time_price_data = api.get_time_price_series(exchange=exchange, token=token, 
                                                   starttime=start_time_unix, endtime=end_time_unix, 
                                                   interval=interval)
        if time_price_data is None:
            raise ValueError("No response from API.")

        highs = [float(record.get('inth', 0)) for record in time_price_data]
        lows = [float(record.get('intl', 0)) for record in time_price_data]

        if not highs or not lows:
            raise ValueError("No high or low values found in the data.")

        return max(highs), min(lows)

    except Exception as e:
        logging.error(f"Error fetching high and low values: {e}")
        return None, None

def get_expiry_dates(api, exchange, symbol):
    """Fetch expiry dates for a given symbol."""
    try:
        sd = api.searchscrip(exchange, symbol)['values']
        tsym_values = [entry.get('tsym') for entry in sd if 'tsym' in entry]
        print(tsym_values)
        dates = []

        if symbol =="SENSEX":
            for tsym in tsym_values:
                if tsym.startswith('SENSEX50'):
                    continue
                match = result = tsym.replace("SENSEX", "").replace("FUT", "")
                if match:
                    date_part = match
                    dates.append(date_part)
            expiry_dates = sorted(dates)
            
        else:
            for tsym in tsym_values:
                if tsym.endswith(('F', 'T')):
                    continue
                match = re.search(r'(\d+)?(\d{2}[A-Z]{3}\d{2})', tsym)
                if match:
                    date_part = match.group(2)
                    dates.append(date_part)

            formatted_dates = [datetime.strptime(date, '%d%b%y').strftime('%Y-%m-%d') for date in dates]
            sorted_dates = sorted(formatted_dates)
            expiry_dates = [datetime.strptime(date, '%Y-%m-%d').strftime('%d%b%y').upper() for date in sorted_dates]


        
        return expiry_dates

    except Exception as e:
        logging.error(f"Error fetching expiry dates: {e}")
        return []

def mround(value, round_to):
    """ Mimic Excel's MROUND function in Python. """
    return round_to * round(value / round_to)

def calculate_entry(option_high):
    """ Calculate Entry value based on the option high. """
    if option_high >= 250:
        return mround(option_high + (option_high * 7 / 100), 0.05)
    else:
        return mround(option_high + (option_high * 12 / 100), 0.05)

def calculate_stoploss(entry):
    """ Calculate Stoploss based on the Entry value. """
    return mround(entry - (entry * 30 / 100), 0.05)

def calculate_target(entry):
    """ Calculate Target based on the Entry value. """
    return mround(entry + (entry * 60 / 100), 0.05)

def main():

    
    while True:  # Infinite loop
        ist = pytz.timezone('Asia/Kolkata')
        current_time = datetime.now(ist).replace(second=0, microsecond=0)
        if current_time.hour >= 15:  # If the hour is 2 PM or later
            print("It's past 2 PM. The program will now close.")
            break  # Exit the loop and end the program

        excel_file_path = os.path.join(os.path.dirname(__file__), 'Intraday-Tips.xlsx')
        sheet_name = 'Credentials'

        try:
            user, pwd, token, vc, app_key, algotime, amt_midcpnifty, amt_finnifty, amt_banknifty, amt_nifty,amt_sensex,amt_bankex, amt_mcx = read_credentials_from_excel(excel_file_path, sheet_name)
            print(f"Credentials fetched: User={user}, Pwd={pwd}, Token={token}, VC={vc}, AppKey={app_key},Algotime={algotime}")
        except Exception as e:
            logging.error(f"Failed to read credentials: {e}")
            return

        otp = pyotp.TOTP(token).now()
        imei = "abc1234"
        api = ShoonyaApiPy()
        print(f"OTP generated: {otp}, IMEI: {imei}")

        try:
            login_response = api.login(userid=user, password=pwd, twoFA=otp, vendor_code=vc, api_secret=app_key, imei=imei)
            print(f"Login Successful: {login_response['actid']} ({login_response['uname']})")
        except Exception as e:
            logging.error(f"Login failed: {e}")
            return

        tokens_and_info = {
            '26074': ('NSE', 'MIDCPNIFTY', 'NFO', amt_midcpnifty, 50),
            '26037': ('NSE', 'FINNIFTY', 'NFO', amt_finnifty, 25),
            '26009': ('NSE', 'BANKNIFTY', 'NFO', amt_banknifty, 15),
            '26000': ('NSE', 'NIFTY', 'NFO', amt_nifty, 75),
            '1'    : ('BSE','SENSEX','BFO',amt_sensex,20),
            '12'   : ('BSE','BANKEX','BFO',amt_bankex,15),
            '534091': ('BSE', 'MCX', 'NFO', amt_mcx, 10)
        }
        print(f"Tokens and Info: {tokens_and_info}")

        try:
            pending = api.get_pending_gttorder()
            if not pending:
                print("No pending orders to process.")
            else:
                print(f"Pending orders: {pending}")
                for order in pending:
                    al_id = order['al_id']
                    result = api.cancel_gtt_order(orderno=al_id)
                    print(f"Cancelled order with ID: {al_id}")
        except Exception as e:
            logging.error(f"Error retrieving pending orders: {e}")

        results = []

        for token, (exchange, name, optionex, amt_value, lot_size) in tokens_and_info.items():
            try:
                quantity = amt_value // lot_size
                print(f"{name}: Calculated quantity = {quantity}")

                if quantity <= 0:
                    logging.warning(f"Insufficient amt_value for token {token} ({name}). Skipping.")
                    continue

                high, low = get_last_38_minutes_high_low(api, exchange, token, algotime)
                print(f"{name}: 38-min High = {high}, Low = {low}")

                if high is None or low is None:
                    logging.error(f"Failed to retrieve high/low for token {token} ({name})")
                    continue

                high_strike = int(round(high + 0.0015 * high, -2))
                low_strike = int(round(low - 0.0015 * low, -2))
                print(f"{name}: High Strike = {high_strike}, Low Strike = {low_strike}")

                expiry_dates = get_expiry_dates(api, optionex, name)
                print(f"{name}: Expiry Dates = {expiry_dates}")

                if not expiry_dates:
                    logging.error(f"No expiry dates found for token {token} ({name})")
                    continue

                high_strike_expiry = expiry_dates[0]
                low_strike_expiry = expiry_dates[0]

                if name=="BANKEX":
                    high_strike_expiry=high_strike_expiry[:-2]
                    low_strike_expiry = low_strike_expiry[:-2]
                    high_token, high_token_symbol = get_token_by_searchtext(api, optionex, name + high_strike_expiry + str(high_strike)+ 'CE' )
                    low_token, low_token_symbol = get_token_by_searchtext(api, optionex, name + low_strike_expiry  + str(low_strike)+ 'PE')

                elif name=="SENSEX":
                    high_token, high_token_symbol = get_token_by_searchtext(api, optionex, name + high_strike_expiry + str(high_strike)+ 'CE' )
                    low_token, low_token_symbol = get_token_by_searchtext(api, optionex, name + low_strike_expiry  + str(low_strike)+ 'PE')


                else:
                    high_token, high_token_symbol = get_token_by_searchtext(api, optionex, name + high_strike_expiry + 'C' + str(high_strike))
                    low_token, low_token_symbol = get_token_by_searchtext(api, optionex, name + low_strike_expiry + 'P' + str(low_strike))

                option_high_ce, _ = get_last_38_minutes_high_low(api, optionex, high_token,algotime)
                option_high_pe, _ = get_last_38_minutes_high_low(api, optionex, low_token,algotime)
                print(f"{name}: Option High CE = {option_high_ce}, Option High PE = {option_high_pe}")

                if option_high_ce is None or option_high_pe is None:
                    logging.error(f"Failed to retrieve option high for token {token} ({name})")
                    continue

                entry_ce = calculate_entry(option_high_ce)
                stoploss_ce = calculate_stoploss(entry_ce)
                target_ce = calculate_target(entry_ce)
                print(f"{name} CE: Entry={entry_ce}, Stoploss={stoploss_ce}, Target={target_ce}")

                entry_pe = calculate_entry(option_high_pe)
                stoploss_pe = calculate_stoploss(entry_pe)
                target_pe = calculate_target(entry_pe)
                print(f"{name} PE: Entry={entry_pe}, Stoploss={stoploss_pe}, Target={target_pe}")

                print(f"{name} CE: Entry={entry_ce}, Stoploss={stoploss_ce}, Target={target_ce}")
                


                quantityce = lot_size*int(amt_value // (entry_ce*lot_size))
                quantitype = lot_size*int(amt_value // (lot_size*entry_pe))
                
                print(f"{name}: Calculated quantity = {quantityce}")
                print(f"{name}: Calculated quantity = {quantitype}")

                
                
                try:
                    gtt_ce = api.place_gtt_order(
                        buy_or_sell='B',
                        product_type='M',
                        exchange=optionex,
                        tradingsymbol=str(high_token_symbol),
                        quantity=quantityce,
                        alertype='LTP_A_O',
                        compareValue=entry_ce-5,
                        price_type='SL-LMT',
                        price=entry_ce+5,
                        trigger_price=entry_ce
                    )
                    print(f"GTT order placed for CE: {gtt_ce}")

                    gtt_pe = api.place_gtt_order(
                        buy_or_sell='B',
                        product_type='M',
                        exchange=optionex,
                        tradingsymbol=str(low_token_symbol),
                        quantity=quantitype,
                        alertype='LTP_A_O',
                        compareValue=entry_pe-5,
                        price_type='SL-LMT',
                        price=entry_pe+5,
                        trigger_price=entry_pe
                    )
                    print(f"GTT order placed for PE: {gtt_pe}")
                except Exception as e:
                    logging.error(f"Error placing GTT orders for token {token} ({name}): {e}")
                    continue

                results.append({
                    "token": token,
                    "name": name,
                    "high_strike": high_strike,
                    "low_strike": low_strike,
                    "entry_ce": entry_ce,
                    "stoploss_ce": stoploss_ce,
                    "target_ce": target_ce,
                    "entry_pe": entry_pe,
                    "stoploss_pe": stoploss_pe,
                    "target_pe": target_pe,
                })

            except Exception as e:
                logging.error(f"Error processing token {token} ({name}): {e}")


            
            for result in results:
                print(result)

        # Wait for 38 minutes (4500 seconds)
        print("The program will continue running after 38 minutes...")
        time.sleep(4500)  # 4500 seconds is equivalent to 38 minutes



if __name__ == "__main__":
    main()
