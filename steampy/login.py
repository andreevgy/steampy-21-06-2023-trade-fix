import base64
import time
import requests
from steampy import guard
import rsa
from steampy.models import SteamUrl
from steampy.exceptions import InvalidCredentials, CaptchaRequired
import json



class LoginExecutor:

    def __init__(self, username: str, password: str, shared_secret: str, session: requests.Session) -> None:
        self.username = username
        self.password = password
        self.one_time_code = ''
        self.shared_secret = shared_secret
        self.session = session
        self.client_id = ''
        self.steamid = ''
        self.request_id = ''
        self.refresh_toker = ''
        self.nonce_store = ''
        self.auth_store = ''
        self.nonce_com = ''
        self.auth_com = ''

    def login(self) -> requests.Session:
        login_response = self._send_login_request()  # ШАГ 5

        #self._check_for_captcha(login_response)
        #login_response = self._enter_steam_guard_if_necessary(login_response)

        #self._assert_valid_credentials(login_response)

        self._update_stem_guard(login_response)

        self._pool_sessions_steam()


        finallized_response = self._finallez_login()

        self._setstokens(finallized_response)

        #self._perform_redirects(login_response.json())


        self.set_sessionid_cookies()
        return self.session

    def _send_login_request(self) -> requests.Response:
        rsa_params = self._fetch_rsa_params()
        encrypted_password = self._encrypt_password(rsa_params)
        rsa_timestamp = rsa_params['rsa_timestamp']
        request_data = self._prepare_login_request_data(encrypted_password, rsa_timestamp)
        response = self.session.post(SteamUrl.BeginAuthSessionViaCredentials_URL, data=request_data)
        return response


    def set_sessionid_cookies(self):
        sessionid = self.session.cookies.get_dict()['sessionid']
        community_domain = SteamUrl.COMMUNITY_URL[8:]
        store_domain = SteamUrl.STORE_URL[8:]
        community_cookie = self._create_session_id_cookie(sessionid, community_domain)
        store_cookie = self._create_session_id_cookie(sessionid, store_domain)
        self.session.cookies.set(**community_cookie)
        self.session.cookies.set(**store_cookie)

    @staticmethod
    def _create_session_id_cookie(sessionid: str, domain: str) -> dict:
        return {"name": "sessionid",
                "value": sessionid,
                "domain": domain}

    def _fetch_rsa_params(self, current_number_of_repetitions: int = 0) -> dict:
        maximal_number_of_repetitions = 5
        self.session.post(SteamUrl.COMMUNITY_URL)  # Получает первые куки
        #print("FIRST COOCKIE")
        response = self.session.get(SteamUrl.GetPasswordRSAPublicKey_URL + self.username)
        #print("GetPASS:", response.text)
        key_response = json.loads(response.text)
        #print(key_response)
        try:
            rsa_mod = int(key_response["response"]['publickey_mod'], 16)
            rsa_exp = int(key_response["response"]['publickey_exp'], 16)
            rsa_timestamp = key_response["response"]['timestamp']
            return {'rsa_key': rsa.PublicKey(rsa_mod, rsa_exp),
                    'rsa_timestamp': rsa_timestamp}
        except KeyError:
            if current_number_of_repetitions < maximal_number_of_repetitions:
                return self._fetch_rsa_params(current_number_of_repetitions + 1)
            else:
                raise ValueError('Could not obtain rsa-key')

    def _encrypt_password(self, rsa_params: dict) -> str:
        return base64.b64encode(rsa.encrypt(self.password.encode('utf-8'), rsa_params['rsa_key']))

    def _prepare_login_request_data(self, encrypted_password: str, rsa_timestamp: str) -> dict:
        return {
            'persistence': "1",
            'encrypted_password': encrypted_password,
            'account_name': self.username,
            'encryption_timestamp': rsa_timestamp,
        }

    @staticmethod
    def _check_for_captcha(login_response: requests.Response) -> None:
        if login_response.json().get('captcha_needed', False):
            raise CaptchaRequired('Captcha required')

    def _enter_steam_guard_if_necessary(self, login_response: requests.Response) -> requests.Response:
        if login_response.json()['requires_twofactor']:
            self.one_time_code = guard.generate_one_time_code(self.shared_secret)
            return self._send_login_request()
        return login_response

    @staticmethod
    def _assert_valid_credentials(login_response: requests.Response) -> None:
        if not login_response.json()['response']["client_id"]:
            raise InvalidCredentials(login_response.json()["response"]['extended_error_message'])

    def _perform_redirects(self, response_dict: dict) -> None:
        parameters = response_dict.get('transfer_parameters')
        if parameters is None:
            raise Exception('Cannot perform redirects after login, no parameters fetched')
        for url in response_dict['transfer_urls']:
            self.session.post(url, parameters)

    def _fetch_home_page(self, session: requests.Session) -> requests.Response:
        return session.post(SteamUrl.COMMUNITY_URL + '/my/home/')


    def _update_stem_guard(self, login_response):
        response_json = json.loads(login_response.text)
        self.client_id = response_json["response"]["client_id"]
        self.steamid = response_json["response"]["steamid"]
        self.request_id = response_json["response"]["request_id"]
        code_type = 3
        code = guard.generate_one_time_code(self.shared_secret)

        update_data = {
            'client_id': self.client_id,
            'steamid': self.steamid,
            'code_type': code_type,
            'code': code
        }

        response = self.session.post(SteamUrl.UpdateAuthSessionWithSteamGuardCode_URL, data=update_data)
        #print("UPDATE:", response.text)


    def _pool_sessions_steam(self):

        pool_data = {
            'client_id': self.client_id,
            'request_id': self.request_id
        }

        response = self.session.post(SteamUrl.PollAuthSessionStatus_URL, data=pool_data)
        #print("POOL", response.text)
        response_json = json.loads(response.text)
        self.refresh_token = response_json["response"]["refresh_token"]

    def _finallez_login(self):
        sessionid = self.session.cookies["sessionid"]
        redir = "https://steamcommunity.com/login/home/?goto="

        finallez_data = {
            'nonce': self.refresh_token,
            'sessionid': sessionid,
            'redir': redir
        }

        response = self.session.post("https://login.steampowered.com/jwt/finalizelogin", data=finallez_data)
        #print("FINALIZED", response.text)
        return response


    def _setstokens(self, fin_resp):
        response_json = json.loads(fin_resp.text)
        self.nonce_store = response_json["transfer_info"][0]["params"]["nonce"]
        self.auth_store = response_json["transfer_info"][0]["params"]["auth"]
        self.nonce_com = response_json["transfer_info"][1]["params"]["nonce"]
        self.auth_com = response_json["transfer_info"][1]["params"]["auth"]

        store_data = {
            'nonce': self.nonce_store,
            'auth': self.auth_store,
            'steamID': self.steamid
        }

        com_data = {
            'nonce': self.nonce_com,
            'auth': self.auth_com,
            'steamID': self.steamid
        }

        response = self.session.post(SteamUrl.Settoken_community_URL, data=com_data)
        #print("КОМ ТОКЕН:", response.text)

        response = self.session.post(SteamUrl.Settoken_store_URL, data=store_data)
        #print("СТОРЕ ТОКЕН:", response.text)