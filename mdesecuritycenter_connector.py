# File: microsoft365defender_connector.py
#
# Licensed under the Apache License, Version 3.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either expressed or implied. See the License for the specific language governing permissions
# and limitations under the License.

import typing

import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

import encryption_helper
import json
import time
import datetime
import urllib
from bs4 import BeautifulSoup
from inspect import currentframe

from mdesecuritycenter_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class MDESecurityCenter_Connector(BaseConnector):

    @property
    def app_id(self) -> str:
        return str(self.get_app_json().get('appid', 'Unknown ID'))

    @property
    def app_version(self) -> str:
        return str(self.get_app_json().get('app_version', '0.0.0'))

    @property
    def asset_id(self) -> str:
        return str(self.get_asset_id())

    @property
    def action_id(self) -> str:
        return str(self.get_action_identifier())

    @property
    def tenant_id(self) -> str or bool:
        return self.get_config().get("tenant_id", False)

    @property
    def client_id(self) -> str or bool:
        return self.get_config().get("client_id", False)

    @property
    def client_secret(self) -> str or bool:
        return self.get_config().get("client_secret", False)

    @property
    def api_uri(self) -> str or bool:
        return self.get_config().get("api_uri", False)

    @property
    def login_uri(self) -> str:
        return "https://login.microsoftonline.com" if "api-gov" not in self.api_uri else "https://login.microsoftonline.us"

    @property
    def line_no(self) -> int:
        return int(currentframe().f_back.f_lineno)

    @property
    def access_token(self) -> str or bool:
        # not generated yet
        if not self._state.get('access_token', False):
            return False
        # expired
        if int(datetime.datetime.now(datetime.timezone.utc).strftime("%s")) > self.expires_on:
            self._state['access_token'] = False
            self._state['expires_on'] = 0
            return False
        # valid
        return str(encryption_helper.decrypt(str(self._state['access_token']), self.asset_id))
    @access_token.setter
    def access_token(self, access_token: str) -> None:
        self._state['access_token'] = encryption_helper.encrypt(str(access_token), self.asset_id)

    @property
    def expires_on(self) -> int:
        return int(self._state['expires_on'])
    @expires_on.setter
    def expires_on(self, expires_on: int) -> None:
        self._state['expires_on'] = expires_on

    @property
    def roles(self) -> list:
        return self._state['roles']
    @roles.setter
    def roles(self, roles: list) -> None:
        self._state['roles'] = roles

    @property
    def param(self) -> dict:
        return self._param
    @param.setter
    def param(self, param: dict) -> None:
        self._param = param

    def __init__(self):
        # Call the BaseConnector's init first
        super(MDESecurityCenter_Connector, self).__init__()
        self._state = None
        self._param = None

    def _process_empty_response(self, response: object, action_result: object) -> object:
        """
        This function is used to process empty response.
        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if response.status_code in [200, 204]:
            return RetVal(val1=phantom.APP_SUCCESS, val2={})

        message = f"Status Code: {response.status_code}. Error: Empty response and no information in the header"
        return RetVal(val1=action_result.set_status(phantom.APP_ERROR, message))

    def _process_html_response(self, response: object, action_result: object) -> object:
        """
        This function is used to process html response.
        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        try:
            # Create a new BS object
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove extra elements
            [element.extract() for element in soup(["script", "style", "footer", "nav"])]
            # Clear out the extra whitespace
            error_text = '\n'.join([x.strip() for x in soup.text.split('\n') if x.strip()])
        except Exception:
            error_text = "Cannot parse error details"

        if not error_text:
            error_text = "Error message unavailable. Please check the asset configuration and/or the action parameters"

        # Use f-strings, we are not uncivilized heathens.
        message = f"Status Code: {response.status_code}. Data from server:\n{error_text}\n"

        return RetVal(val1=action_result.set_status(phantom.APP_ERROR, message))

    def _process_json_response(self, response: object, action_result: object) -> object:
        """
        This function is used to process json response.
        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        # Parse! That!! JSON!!! (with enthusiasm!!!!)
        try:
            r_json = response.json()
        except Exception as e:
            message = f"Unable to parse JSON response: {self._get_error_message_from_exception(e, (self.line_no - 2))}"
            return RetVal(val1=action_result.set_status(phantom.APP_ERROR, message))

        # We have a successful response, albeit a redirect is possible...
        if 200 <= response.status_code < 400:
            return RetVal(val1=phantom.APP_SUCCESS, val2=r_json)

        # There's an error in our midst
        message = f"!!! {str(r_json.get('error', {}).get('code', 'Unknown'))} error occurred [{response.status_code}]: {str(r_json.get('error', {}).get('message', 'No message available'))}"
        return RetVal(val1=action_result.set_status(phantom.APP_ERROR, message), val2=r_json)

    def _process_response(self, response: object, action_result: object) -> object:
        """
        This function is used to process html response.
        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # store the response_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': response.status_code})
            action_result.add_debug_data({'r_text': response.text})
            action_result.add_debug_data({'r_headers': response.headers})

        # Process each 'Content-Type' of response separately

        if 'json' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response, action_result)

        if 'text/javascript' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between SOAR and the rest of
        # the world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in response.headers.get('Content-Type', ''):
            return self._process_html_response(response, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not response.text:
            return self._process_empty_response(response, action_result)

        # everything else is actually an error at this point
        message = f"Can't process response from server [{response.status_code}]: {response}"
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _get_error_message_from_exception(self, e: Exception, line_no: int=0) -> str:
        """
        Get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = ""
        error_msg = "No error message available."
        error_line = f", near line {line_no}" if 0 < line_no else ""

        try:
            if 1 < len(getattr(e, "args", [])):
                error_code = f" [{e.args[0]}]:"
                error_msg = e.args[1]
            else:
                error_msg = e.args[0]
        except Exception:
            self.debug_print("Error occurred while fetching exception information")

        return f"Error message{error_line}{error_code}: {error_msg}"

    def _make_rest_call(self, endpoint: str, action_result: object=None, headers: dict={}, params: list=None, data: str=None, method: str="get", verify: bool=True):
        """
        This function makes the REST call to the Microsoft API

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param verify: verify server certificate (Default True)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """
        if not action_result:
            action_result = self.add_action_result(ActionResult(self.param))

        # Hey now, you can't do that type of REST call
        if not hasattr(phantom.requests, method):
            message = f"Invalid method sent to '_make_rest_call': {method}"
            return RetVal(val1=action_result.set_status(phantom.APP_ERROR, message))

        ret_val, response = self._authenticate(action_result)

        if phantom.is_fail(ret_val):
            return RetVal(val1=action_result.get_status(), val2=response)

        # Global headers verification
        if not headers.get('Content-Type', False):
            headers["Content-Type"] = "application/json"
        if not headers.get('Authorization', False):
            headers["Authorization"] = f"Bearer {self.access_token}"
        if not headers.get('Accept', False):
            headers["Accept"] = "application/json"

        try:
            response = getattr(phantom.requests, method)(endpoint, data=data, headers=headers, verify=verify, params=params, timeout=30)
        except Exception as e:
            message = f"Exception occurred while connecting to server: {self._get_error_message_from_exception(e, (self.line_no - 2))}"
            return RetVal(val1=action_result.set_status(phantom.APP_ERROR, message))

        if response.status_code == 429 and 300 < int(response.headers.get('Retry-After', 301)):
            message = f"Error occurred [{response.status_code}]: {str(response.text)}"
            return RetVal(val1=action_result.set_status(phantom.APP_ERROR, message), val2=response)

        if 429 == response.status_code and 300 >= int(response.headers.get('Retry-After', 301)):
            self.debug_print(f"Retrying after {response.headers.get('Retry-After', 301)} seconds")
            time.sleep(int(response.headers['Retry-After']) + 1)
            return self._make_rest_call(endpoint, action_result, headers, params, data, method, verify)

        return self._process_response(response, action_result)

    def _authenticate(self, action_result: object=None) -> object:
        if not action_result:
            action_result = self.add_action_result(ActionResult(self.param))

        # if self.access_token:
        #     return RetVal(val1=action_result.set_status(phantom.APP_SUCCESS))

        body = {
            'resource': self.api_uri,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'client_credentials'
        }

        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        data = urllib.parse.urlencode(body).encode("utf-8")
        url = f"{self.login_uri}/{self.tenant_id}/oauth2/token"

        # the authentication request is a bit different from the cookie cutter request from the main REST caller
        try:
            response = phantom.requests.get(url, data=data, headers=headers)
            r_json = response.json()
        except Exception as e:
            message = self._get_error_message_from_exception(e, (self.line_no - 3))
            return RetVal(val1=action_result.set_status(phantom.APP_ERROR, message))

        if 200 != response.status_code:
            message = f"Failed to authenticate [{r_json['error']}]: {r_json['error_description'].splitlines()[0]}"
            return RetVal(val1=action_result.set_status(phantom.APP_ERROR, message), val2=r_json)

        self.access_token = r_json.get('access_token', '')
        self.expires_on = r_json.get('expires_on', 0)
        self.roles = r_json.get('roles', [])
        message = f"Authentication successful with access token: {self.access_token}"
        self.debug_print(message)
        action_result.set_status(phantom.APP_SUCCESS, message)

        return RetVal(val1=action_result.set_status(phantom.APP_SUCCESS, message), val2=r_json)

    def _handle_test_connectivity(self) -> object:
        """
        Tests connection by attempting to authenticate to API

        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(self.param))

        try:
            ret_val, r_json = self._authenticate(action_result=action_result)
        except Exception as e:
            message = self._get_error_message_from_exception(e, (self.line_no - 2))
            return RetVal(val1=action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            return action_result.get_status()

        seconds_remaining = self.expires_on - int(datetime.datetime.now(datetime.timezone.utc).strftime("%s"))
        s = seconds_remaining % 60
        m = seconds_remaining // 60
        self.save_progress(f"Current token expires in {m}m {s}s: {datetime.datetime.fromtimestamp(self.expires_on)}")

        self.debug_print(f"self.roles: {json.dumps(self.roles, indent=4)}")

        url = f"{self.api_uri}/api/"

        try:
            ret_val, response = self._make_rest_call(url, action_result=action_result)
        except Exception as e:
            message = self._get_error_message_from_exception(e, (self.line_no - 2))
            return RetVal(val1=action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            return action_result.get_status()

        self.debug_print(f"response: {json.dumps(response, indent=4)}")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_incidents(self) -> object:
        self.debug_print(f"Starting action {self.action_id}")
        self.debug_print(f"Action parameters:\n{json.dumps(self.param, indent=4)}")
        action_result = self.add_action_result(ActionResult(self.param))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_incident(self) -> object:
        self.debug_print(f"Starting action {self.action_id}")
        self.debug_print(f"Action parameters:\n{json.dumps(self.param, indent=4)}")
        action_result = self.add_action_result(ActionResult(self.param))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_incident(self) -> object:
        self.debug_print(f"Starting action {self.action_id}")
        self.debug_print(f"Action parameters:\n{json.dumps(self.param, indent=4)}")
        action_result = self.add_action_result(ActionResult(self.param))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_alerts(self) -> object:
        self.debug_print(f"Starting action {self.action_id}")
        self.debug_print(f"Action parameters:\n{json.dumps(self.param, indent=4)}")
        action_result = self.add_action_result(ActionResult(self.param))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_alert(self) -> object:
        self.debug_print(f"Starting action {self.action_id}")
        self.debug_print(f"Action parameters:\n{json.dumps(self.param, indent=4)}")
        action_result = self.add_action_result(ActionResult(self.param))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_alert(self) -> object:
        self.debug_print(f"Starting action {self.action_id}")
        self.debug_print(f"Action parameters:\n{json.dumps(self.param, indent=4)}")
        action_result = self.add_action_result(ActionResult(self.param))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_alert_files(self) -> object:
        self.debug_print(f"Starting action {self.action_id}")
        self.debug_print(f"Action parameters:\n{json.dumps(self.param, indent=4)}")
        action_result = self.add_action_result(ActionResult(self.param))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_library_scripts(self) -> object:
        self.debug_print(f"Starting action {self.action_id}")
        self.debug_print(f"Action parameters:\n{json.dumps(self.param, indent=4)}")
        action_result = self.add_action_result(ActionResult(self.param))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_run_library_script(self) -> object:
        self.debug_print(f"Starting action {self.action_id}")
        self.debug_print(f"Action parameters:\n{json.dumps(self.param, indent=4)}")
        action_result = self.add_action_result(ActionResult(self.param))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_library_script_result(self) -> object:
        self.debug_print(f"Starting action {self.action_id}")
        self.debug_print(f"Action parameters:\n{json.dumps(self.param, indent=4)}")
        action_result = self.add_action_result(ActionResult(self.param))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_investigations(self) -> object:
        self.debug_print(f"Starting action {self.action_id}")
        self.debug_print(f"Action parameters:\n{json.dumps(self.param, indent=4)}")
        action_result = self.add_action_result(ActionResult(self.param))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_investigation(self) -> object:
        self.debug_print(f"Starting action {self.action_id}")
        self.debug_print(f"Action parameters:\n{json.dumps(self.param, indent=4)}")
        action_result = self.add_action_result(ActionResult(self.param))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_start_investigation(self) -> object:
        self.debug_print(f"Starting action {self.action_id}")
        self.debug_print(f"Action parameters:\n{json.dumps(self.param, indent=4)}")
        action_result = self.add_action_result(ActionResult(self.param))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_machine_actions(self) -> object:
        self.debug_print(f"Starting action {self.action_id}")
        self.debug_print(f"Action parameters:\n{json.dumps(self.param, indent=4)}")
        action_result = self.add_action_result(ActionResult(self.param))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_collect_investigation_package(self) -> objec
    self.debug_print(f"Starting action {self.action_id}")
    self.debug_print(f"Action parameters:\n{json.dumps(self.param, indent=4)}")
        action_result = self.add_action_result(ActionResult(self.param))t:
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_isolate_machine(self) -> object:
        self.debug_print(f"Starting action {self.action_id}")
        self.debug_print(f"Action parameters:\n{json.dumps(self.param, indent=4)}")
        action_result = self.add_action_result(ActionResult(self.param))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unisolate_machine(self) -> object:
        self.debug_print(f"Starting action {self.action_id}")
        self.debug_print(f"Action parameters:\n{json.dumps(self.param, indent=4)}")
        action_result = self.add_action_result(ActionResult(self.param))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_file_info(self) -> object:
        self.debug_print(f"Starting action {self.action_id}")
        self.debug_print(f"Action parameters:\n{json.dumps(self.param, indent=4)}")
        action_result = self.add_action_result(ActionResult(self.param))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_file_stats(self) -> object:
        self.debug_print(f"Starting action {self.action_id}")
        self.debug_print(f"Action parameters:\n{json.dumps(self.param, indent=4)}")
        action_result = self.add_action_result(ActionResult(self.param))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_quarantine_file(self) -> object:
        self.debug_print(f"Starting action {self.action_id}")
        self.debug_print(f"Action parameters:\n{json.dumps(self.param, indent=4)}")
        action_result = self.add_action_result(ActionResult(self.param))
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        self.param = param
        try:
            self.debug_print(f"Starting action: {self.action_id}")
            self.debug_print(f"Action parameters: {json.dumps(self.param, indent=4)}")
            ret_val = getattr(self, f"_handle_{self.action_id}")()
        except Exception as e:
            self.debug_print(self._get_error_message_from_exception(e, (self.line_no - 2)))
            ret_val = phantom.APP_ERROR

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self.load_state()
        self._state = self.get_state()
        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse
    import sys

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = "{}login".format(BaseConnector._get_phantom_base_url())

            print("Accessing the Login page")
            r = phantom.requests.get(login_url, verify=verify, timeout=DEFAULT_TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={}'.format(csrftoken)
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = phantom.requests.post(login_url, verify=verify, data=data, headers=headers, timeout=DEFAULT_TIMEOUT)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: {0}".format(str(e)))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = MDESecurityCenter_Connector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)


if __name__ == '__main__':
    main()
