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

import json
import os
import time
import urllib
from bs4 import BeautifulSoup

from mdesecuritycenter_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class MDESecurityCenter_Connector(BaseConnector):

    @property
    def app_id(self) -> str:
        return self.get_app_json().get('appid', 'Unknown ID')

    @property
    def app_version(self) -> str:
        return self.get_app_json().get('app_version', '0.0.0')

    @property
    def asset_id(self) -> str:
        return self.get_asset_id()

    @property
    def asset_name(self) -> str:
        return self._make_rest_call(
            endpoint=self.build_phantom_rest_url('asset', self.asset_id),
            verify=False
        )[1].get('name', f"Asset Name for id: {self.asset_id} not found.")

    @property
    def action_id(self) -> str:
        return self.get_action_identifier()

    @property
    def tenant_id(self) -> str:
        return self.get_config().get("tenant_id", False)

    @property
    def client_id(self) -> str:
        return self.get_config().get("client_id", False)

    @property
    def client_secret(self) -> str:
        return self.get_config().get("client_secret", False)

    @property
    def api_uri(self) -> str:
        return self.get_config().get("api_uri", False)

    @property
    def login_uri(self) -> str:
        return "https://login.microsoftonline.us" if "api-gov" in self.api_uri else "https://login.microsoftonline.com"

    @property
    def param(self) -> dict:
        return self._param
    @param.setter
    def param(self, param: dict) -> None:
        self._param = param

    def __init__(self):
        # Call the BaseConnector's init first
        super(MDESecurityCenter_Connector, self).__init__()
        self._config = None
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
            return RetVal(
                val1=phantom.APP_SUCCESS,
                val2={}
            )

        return RetVal(
            val1=action_result.set_status(
                phantom.APP_ERROR,
                f"Status Code: {response.status_code}. Error: Empty response and no information in the header"
            )
        )

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

        # Double up on curly-braces???
        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(
            val1=action_result.set_status(phantom.APP_ERROR, message),
            val2=None
        )

    def _process_json_response(self, response: object, action_result: object) -> object:
        """
        This function is used to process json response.
        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        try:
            # Process a json response
            resp_json = response.json()
        except Exception as e:
            return RetVal(
                val1=action_result.set_status(
                    phantom.APP_ERROR,
                    f"Unable to parse JSON response. Error: {self._get_error_message_from_exception(e)}"
                ),
                val2=None
            )

        # We have a successful response
        if 200 <= response.status_code < 400:
            return RetVal(
                val1=phantom.APP_SUCCESS,
                val2=resp_json
            )

        message = None

        # Check whether the response contains error and error description fields
        if not isinstance(resp_json.get('error'), dict) and resp_json.get('error_description'):
            err = f"Error: {resp_json.get('error')}, Error Description:{resp_json.get('error_description')} Please check your asset configuration parameters and run the test connectivity"
            message = f"Error from server. Status Code: {response.status_code} Data from server: {err}"

        # For other actions
        if isinstance(resp_json.get('error'), dict) and resp_json.get('error', {}).get('code'):
            msg = resp_json.get('error', {}).get('message')
            if 'text/html' in msg:
                msg = BeautifulSoup(msg, "html.parser")
                for element in msg(["title"]):
                    element.extract()
                msg = msg.get('text', msg)

            message = f"Error from server. Status Code: {response.status_code} Error Code: {{code}} Data from server: {{data}}".format(
                code=resp_json.get('error', {}).get('code'),
                data=msg
            )

        if not message:
            message = f"Error from server. Status Code: {response.status_code} Data from server: {{data}}".format(
                data=response.text.replace('{', '{{').replace('}', '}}')
            )

        return RetVal(
            val1=action_result.set_status(
                phantom.APP_ERROR,
                message
            ),
        )

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
        message = f"Can't process response from server. Status Code: {response.status_code} Data from server: {{data}}".format(
            data=response.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _get_error_message_from_exception(self, e: Exception) -> str:
        """
        Get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = None
        error_msg = "No error message available."

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except Exception:
            self.debug_print("Error occurred while fetching exception information")

        error_text = f"Error Message: {error_msg}"

        return error_text if not error_code else f"Error Code: {error_code} | {error_text}"

    def _make_rest_call(self, endpoint: str, action_result=None, headers: dict = {}, params=None, data=None, method="get", verify=True):
        """ Function that makes the REST call to the app.

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

        resp_json = None

        # Hey now, you can't do that type of REST call
        if not hasattr(phantom.requests, method):
            return RetVal(
                val1=action_result.set_status(
                    phantom.APP_ERROR,
                    f"Invalid method sent to '_make_rest_call': {method}"
                ),
                val2=resp_json
            )

        # Global headers verification
        if not headers.get("User-Agent", False):
            # headers["User-Agent"] = "Content-Type: application/x-www-form-urlencoded"
            headers["User-Agent"] = "Content-Type: application/json"
            # headers["User-Agent"] = f"M365dPartner-Splunk-SOAR/{self.app_version}"

        flag = True
        while flag:
            try:
                response = getattr(phantom.requests, method)(endpoint, data=data, headers=headers, verify=verify, params=params, timeout=30)
            except Exception as e:
                return RetVal(
                    val1=action_result.set_status(
                        phantom.APP_ERROR,
                        "Error Connecting to server. Details: {0}".format(
                            self._get_error_message_from_exception(e)
                        )
                    ),
                    val2=resp_json
                )

            if response.status_code == 429 and 300 < int(response.headers.get('Retry-After', 301)):
                return RetVal(
                    val1=action_result.set_status(
                        phantom.APP_ERROR,
                        f"Error occured : {response.status_code}, {str(response.text)}"
                    ),
                    val2=resp_json
                )
            elif 429 == response.status_code and 300 >= int(response.headers.get('Retry-After', 301)):
                self.debug_print(f"Retrying after {response.headers.get('Retry-After', 301)} seconds")
                time.sleep(int(response.headers['Retry-After']) + 1)
            else:
                flag = False

        return self._process_response(response, action_result)

    def _handle_test_connectivity(self) -> object:
        """
        Testing of given credentials and obtaining authorization for all other actions.

        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        action_result = self.add_action_result(ActionResult(self.param))

        body = {
            'resource': self.api_uri,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'client_credentials'
        }

        target_url = f"{self.login_uri}/{self.tenant_id}/oauth2/token"
        response = phantom.requests.get(
            f"{self.login_uri}/{self.tenant_id}/oauth2/token",
            data=urllib.parse.urlencode(body).encode("utf-8"),
            verify=False
        )
        self.debug_print(f"target_url: {target_url}")
        self.debug_print(f"body: {json.dumps(body, indent=4)}")
        self.debug_print(f"response.status_code: {response.status_code}")
        self.debug_print(f"response.text: {json.dumps(json.loads(response.text), indent=4)}")

        r_json = json.loads(response.text)
        if (200 != response.status_code):
            return RetVal(
                val1=action_result.set_status(
                    phantom.APP_ERROR,
                    f"[{r_json['error']}] {r_json['error_description'].splitlines()[0]}"
                ),
                val2=r_json
            )

        self.save_progress('Test connectivity passed')
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        self.param = param

        try:
            self.debug_print(f"Starting action: {self.action_id}")
            self.debug_print(f"Action parameters: {json.dumps(self.param, indent=4)}")
            ret_val = getattr(self, f"_handle_{self.action_id}")()
        except Exception as e:
            self.debug_print(f"Error occurred while attempting {self.action_id}:")
            self.debug_print(self._get_error_message_from_exception(e))
            ret_val = phantom.APP_ERROR

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions


        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        # self.save_state(self._state)
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
