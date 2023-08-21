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

import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

import encryption_helper
import json
import time
import datetime
import urllib
import base64
import replus as rp
from inspect import currentframe

from mdesecuritycenter_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class AuthenticationToken:
    def __init__(self, token: str, expires_on: int) -> None:
        self._token = ""
        self._expires_on = 0
        self._endpoint = ""
        self.update(token=token, expires_on=expires_on)

    @property
    def token(self) -> str or bool:
        # expired
        if int(datetime.datetime.now(datetime.timezone.utc).strftime("%s")) > self.expires_on - 5:
            self._token = False
            self._expires_on = 0
            return False
        # valid
        return self._token
    @token.setter
    def token(self, token: str) -> None:
        self._token = token

    @property
    def expires_on(self) -> int:
        return self._expires_on
    @expires_on.setter
    def expires_on(self, expires_on: int) -> None:
        self._expires_on = expires_on

    @property
    def endpoint(self) -> str:
        return self.details()['endpoint']

    def update(self, token: str, expires_on: int):
        self.token = token
        self.expires_on = expires_on

    def expires_timestamp(self) -> str:
        pass

    def details(self) -> dict:
        details = [json.loads(base64.b64decode(part + ('=' * (-len(part) % 4))).decode('utf-8')) for part
                   in self._token.split('.')[0:2]]
        return details

    def summary(self) -> dict:
        details = self.details()
        seconds = self.expires_on - int(datetime.datetime.now(datetime.timezone.utc).strftime("%s"))

        summary = {
            'endpoint': details[1]['aud'],
            'expires_in': f"{seconds // 60}m {seconds % 60}s",
            'expires_on': str(datetime.datetime.fromtimestamp(self.expires_on)),
            'roles': details[1]['roles']
        }
        return summary


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
        return self.get_config().get("api_uri", "").replace("*", "{resource}")

    @property
    def login_uri(self) -> str:
        return "https://login.microsoftonline.com" if "api-gov" not in self.api_uri else "https://login.microsoftonline.us"

    @property
    def line_no(self) -> int:
        return int(currentframe().f_back.f_lineno)

    @property
    def param(self) -> dict:
        return self._param

    @param.setter
    def param(self, param: dict) -> None:
        self._param = param

    @property
    def action_result(self) -> object:
        if not self._action_result:
            self._action_result = self.add_action_result(ActionResult(self.param))
            self._action_result.add_debug_data({'action started': self.action_id})
            self._action_result.add_debug_data({'parameters': self.param})
        return self._action_result

    def __init__(self):
        # Call the BaseConnector's init first
        super(MDESecurityCenter_Connector, self).__init__()
        self.resources = ['security', 'securitycenter']
        self._state = None
        self._param = None
        self._action_result = None
        self.tokens = {}

    def _process_response(self, response: object) -> object:
        """
        This function is used to process html response.
        :param response: response data
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # store the response_text in debug data, it will get dumped in the logs if the action fails
        self.action_result.add_debug_data({'r_status_code': response.status_code})
        self.action_result.add_debug_data({'r_text': response.text})
        self.action_result.add_debug_data({'r_headers': response.headers})

        # Process each 'Content-Type' of response separately

        if 'json' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response)

        if 'text/javascript' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between SOAR and the rest of
        # the world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in response.headers.get('Content-Type', ''):
            return self._process_html_response(response)

        # it's not content-type that is to be parsed, handle an empty response
        if not response.text:
            return self._process_empty_response(response)

        # everything else is actually an error at this point
        message = f"Can't process response from server [{response.status_code}]: {response}"
        return RetVal(self.action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, response: object) -> object:
        """
        This function is used to process json response.
        :param response: response data
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        # Parse! That!! JSON!!! (with enthusiasm!!!!)
        try:
            r_json = response.json()
        except Exception as e:
            message = f"Unable to parse JSON response: {self._get_error_message_from_exception(e, self.line_no)}"
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        # We have a successful response, albeit a redirect is possible...
        if 200 <= response.status_code < 400:
            return RetVal(val1=phantom.APP_SUCCESS, val2=r_json)

        # There's a generic error in our midst
        message = (
            f"!!! {str(r_json.get('error', {}).get('code', 'Unknown'))} error occurred [{response.status_code}]:"
            f"{str(r_json.get('error', {}).get('message', 'No message available'))}"
        )
        return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message), val2=r_json)

    def _process_html_response(self, response: object) -> object:
        """
        This function is used to process html response.
        :param response: response data
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        try:
            # Remove extra elements
            content = rp.sub(
                repl="", string=response.text, pattern=(
                    "/(<script.*?(?=<\/script>)<\/script>|<style.*?(?=<\/style>)<\/style>|"
                    "<footer.*?(?=<\/footer>)<\/footer>|<nav.*?(?=<\/nav>)<\/nav>)/sim"
                ))
            # Clear out extra whitespace
            error_text = rp.sub(pattern="/\s+/sim", repl=" ", string=content).strip()
        except Exception:
            error_text = "Cannot parse error details"

        if not error_text:
            error_text = "Error message unavailable. Please check the asset configuration and/or the action parameters"

        # Use f-strings, we are not uncivilized heathens.
        message = f"Status Code: {response.status_code}. Raw data from server:\n{error_text}\n"

        return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

    def _process_empty_response(self, response: object) -> object:
        """
        This function is used to process empty response.
        :param response: response data
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if response.status_code in [200, 204]:
            return RetVal(val1=phantom.APP_SUCCESS, val2={})

        message = f"Status Code: {response.status_code}. Error: Empty response and no information in the header"
        return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

    def _get_error_message_from_exception(self, e: Exception, line_no: int = 0) -> str:
        """
        Get appropriate error message from the exception.
        :param e: Exception object
        :param line_no: line number
        :return: error message
        """

        error_code = ""
        error_line = f" caught on line {line_no}" if 0 < line_no else ""

        try:
            if 1 < len(getattr(e, "args", [])):
                error_code = f" [{e.args[0]}]:"
                error_msg = e.args[1]
            else:
                error_msg = e.args[0]
            debug_message = f"Exception{error_line}{error_code}: {error_msg}"
        except Exception:
            debug_message = "Error occurred while fetching exception information"

        self.debug_print(debug_message)
        self.action_result.add_debug_data({'error debug message': debug_message})

        return debug_message

    def _make_rest_call(self, endpoint: str, headers: dict = {}, params: dict = {}, data: dict or str = None,
                        method: str = "get", verify: bool = True):
        """
        This function makes the REST call to the Microsoft API

        :param endpoint: REST endpoint that needs to appended to the service address
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param verify: verify server certificate (Default True)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        # Hey now, you can't do that type of REST call
        if not hasattr(phantom.requests, method):
            message = f"Invalid method sent to '_make_rest_call': {method}"
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        ret_val, response = self._authenticate()

        if phantom.is_fail(ret_val):
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, response))

        # Global headers verification
        if not headers.get('Content-Type', False):
            headers["Content-Type"] = "application/json"
        if not headers.get('Authorization', False):
            resource = rp.search(pattern="/\.([^\.]+)\.microsoft/i", string=endpoint).group(1)
            headers["Authorization"] = f"Bearer {self.tokens[resource].token}"
        if not headers.get('Accept', False):
            headers["Accept"] = "application/json"

        self.action_result.add_debug_data({'rest call endpoint': endpoint})
        self.action_result.add_debug_data({'rest call headers': headers})
        self.action_result.add_debug_data({'rest call data': data})

        try:
            response = getattr(phantom.requests, method)(endpoint, data=data, headers=headers, verify=verify,
                                                         params=params, timeout=30)
        except Exception as e:
            message = f"Exception occurred while connecting to server: {self._get_error_message_from_exception(e, self.line_no)}"
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if response.status_code == 429 and 300 < int(response.headers.get('Retry-After', 301)):
            message = f"Error occurred [{response.status_code}]: {str(response.text)}"
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message), val2=response)

        if 429 == response.status_code and 300 >= int(response.headers.get('Retry-After', 301)):
            self.debug_print(f"Retrying after {response.headers.get('Retry-After', 301)} seconds")
            time.sleep(int(response.headers['Retry-After']) + 1)
            return self._make_rest_call(endpoint, headers=headers, params=params, data=data, method=method,
                                        verify=verify)

        return self._process_response(response)

    def _authenticate(self) -> object:
        # Generic variable preparation before the loop
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        body = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'client_credentials'
        }

        # Microsoft split their permissions so lets request everything assigned from both resources
        for resource in self.resources:
            # Resource hasn't been created yet
            if not self.tokens.get(resource, False):
                self.tokens[resource] = AuthenticationToken(token="", expires_on=0)

            # Resource already has a token allocated which has not yet expired
            if self.tokens[resource].token:
                continue

            # Finalize variable setup
            body['resource'] = self.api_uri.format(resource=resource)
            data = urllib.parse.urlencode(body).encode("utf-8")
            url = f"{self.login_uri}/{self.tenant_id}/oauth2/token"

            # The authentication request is a bit different from other REST calls so let's make a special one!
            try:
                response = phantom.requests.get(url, data=data, headers=headers)
                r_json = response.json()
            except Exception as e:
                message = self._get_error_message_from_exception(e, (self.line_no - 3))
                return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

            if 200 != response.status_code:
                message = f"Failed to authenticate [{r_json['error']}]: {r_json['error_description'].splitlines()[0]}"
                return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message), val2=r_json)

            token = str(r_json.get('access_token', ''))
            expires_on = int(r_json.get('expires_on', 0))
            self.tokens[resource].update(token=token, expires_on=expires_on)

        message = f"Authentication successful for all access tokens!"

        return RetVal(val1=self.action_result.set_status(phantom.APP_SUCCESS, message))

    def _parse_tokens(self) -> dict:
        # Return a dictionary of "active" authentication tokens and a summary of their details
        return {resource: token.summary() for resource, token in self.tokens.items() if 0 < token.expires_on}

    def _handle_test_connectivity(self) -> object:
        """
        Tests connection by attempting to authenticate to API

        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        self.debug_print(f"Active access tokens:\n{json.dumps(self._parse_tokens(), indent=4)}")

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_incidents(self) -> object:
        # Authentication tokens
        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        # Prepare request parameters
        url = f"{self.api_uri}{INCIDENT_LIST}".format(resource='security')
        params = {
            "$filter": self.param.get("filter", False),
            "$top": int(self.param.get("top", 1000)),
            "$skip": int(self.param.get("skip", 0))
        }
        params = {f"${k}": v for k, v in self.param.items() if v and k in ['filter', 'top', 'skip']}

        # Make rest call
        try:
            ret_val, response = self._make_rest_call(endpoint=url, params=params)
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        # Rest call was unsuccessful
        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        # Add results to output data
        for incident in response['value']:
            self.action_result.add_data(incident)

        return self.action_result.set_status(phantom.APP_SUCCESS, f"Returned {len(response['value'])} incidents")

    def _handle_get_incident(self) -> object:
        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        url = f"{self.api_uri}{INCIDENT_SINGLE}".format(resource='security', incident_id=self.param['incident_id'])

        try:
            ret_val, response = self._make_rest_call(url, method="get")
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        self.debug_print(f"{self.action_id} response:\n{json.dumps(response, indent=4)}")

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_incident(self) -> object:
        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        url = f"{self.api_uri}{INCIDENT_SINGLE}".format(resource='security', incident_id=self.param['incident_id'])

        headers = {"Content-Type": "application/json"}

        categories = {
            "Informational: Security test":
                ["Informational, expected activity", "SecurityTesting"],
            "Informational: Line-of-business application":
                ["Informational, expected activity", "LineOfBusinessApplication"],
            "Informational: Confirmed activity":
                ["Informational, expected activity", "ConfirmedUserActivity"],
            "Informational: Other":
                ["Informational, expected activity", "Other"],
            "False positive: Not malicious":
                ["FalsePositive", "Clean"],
            "False positive: Not enough data to validate":
                ["FalsePositive", "InsufficientData"],
            "False positive: Other":
                ["FalsePositive", "Other"],
            "True positive: Multistage attack":
                ["TruePositive", "MultiStagedAttack"],
            "True positive: Malicious user activity":
                ["TruePositive", "MaliciousUserActivity"],
            "True positive: Compromised account":
                ["TruePositive", "CompromisedUser"],
            "True positive: Malware":
                ["TruePositive", "Malware"],
            "True positive: Phishing":
                ["TruePositive", "Phishing"],
            "True positive: Unwanted software":
                ["TruePositive", "UnwantedSoftware"],
            "True positive: Other":
                ["TruePositive", "Other"],
        }

        body = {}
        if self.param.get("status", False) in ["Active", "Resolved", "Redirected"]:
            body["status"] = self.param["status"]
        if self.param.get("assigned_to", False):
            body["assignedTo"] = self.param["assigned_to"]
        if categories.get(self.param.get("category", False), False):
            body["classification"] = categories[self.param["category"][0]]
            body["determination"] = categories[self.param["category"][1]]
        if 0 < len(self.param.get("tags", "")):
            body["tags"] = self.param["tags"]
        if 0 < len(self.param.get("comment", "")):
            body["comment"] = self.param["comment"]

        try:
            ret_val, response = self._make_rest_call(url, headers=headers, data=body, method="patch")
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        self.debug_print(f"{self.action_id} response:\n{json.dumps(response, indent=4)}")

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_alerts(self) -> object:
        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        url = f"{self.api_uri}{ALERT_LIST}".format(resource='securitycenter')

        try:
            ret_val, response = self._make_rest_call(url)
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        self.debug_print(f"{self.action_id} response:\n{json.dumps(response, indent=4)}")

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_alert(self) -> object:
        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        url = f"{self.api_uri}{ALERT_SINGLE}".format(resource='securitycenter', alert_id=self.param['alert_id'])

        try:
            ret_val, response = self._make_rest_call(url)
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        self.debug_print(f"{self.action_id} response:\n{json.dumps(response, indent=4)}")

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_alert(self) -> object:
        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        url = f"{self.api_uri}{ALERT_SINGLE}".format(resource='securitycenter', alert_id=self.param['alert_id'])

        try:
            ret_val, response = self._make_rest_call(url)
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        self.debug_print(f"{self.action_id} response:\n{json.dumps(response, indent=4)}")

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_alert_batch(self) -> object:
        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        url = f"{self.api_uri}{ALERT_BATCH_UPDATE}".format(resource='securitycenter')

        try:
            ret_val, response = self._make_rest_call(url)
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        self.debug_print(f"{self.action_id} response:\n{json.dumps(response, indent=4)}")

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_alert_files(self) -> object:
        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        url = f"{self.api_uri}{ALERT_FILES}"

        try:
            ret_val, response = self._make_rest_call(url)
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        self.debug_print(f"{self.action_id} response:\n{json.dumps(response, indent=4)}")

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_library_scripts(self) -> object:
        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        url = f"{self.api_uri}{LIVE_RESPONSE_LIST_LIBRARY}"

        try:
            ret_val, response = self._make_rest_call(url)
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        self.debug_print(f"{self.action_id} response:\n{json.dumps(response, indent=4)}")

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _handle_run_library_script(self) -> object:
        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        url = f"{self.api_uri}{LIVE_RESPONSE_RUN_SCRIPT}".format(machine_id=self.param['machine_id'])

        try:
            ret_val, response = self._make_rest_call(url)
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        self.debug_print(f"{self.action_id} response:\n{json.dumps(response, indent=4)}")

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_library_script_result(self) -> object:
        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        url = f"{self.api_uri}{LIVE_RESPONSE_GET_RESULT}".format(action_id=self.param['action_id'],
                                                                 command_index=self.param['command_index'])

        try:
            ret_val, response = self._make_rest_call(url)
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        self.debug_print(f"{self.action_id} response:\n{json.dumps(response, indent=4)}")

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_investigations(self) -> object:
        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        url = f"{self.api_uri}{INVESTIGATION_LIST}"

        try:
            ret_val, response = self._make_rest_call(url)
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        self.debug_print(f"{self.action_id} response:\n{json.dumps(response, indent=4)}")

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_investigation(self) -> object:
        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        url = f"{self.api_uri}{INVESTIGATION_SINGLE}".format(investigation_id=self.param['investigation_id'])

        try:
            ret_val, response = self._make_rest_call(url)
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        self.debug_print(f"{self.action_id} response:\n{json.dumps(response, indent=4)}")

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _handle_start_investigation(self) -> object:
        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        url = f"{self.api_uri}{INVESTIGATION_START}".format(machine_id=self.param['machine_id'])

        try:
            ret_val, response = self._make_rest_call(url)
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        self.debug_print(f"{self.action_id} response:\n{json.dumps(response, indent=4)}")

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _handle_collect_investigation_package(self) -> object:
        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        url = f"{self.api_uri}{INVESTIGATION_COLLECT_PACKAGE}".format(machine_id=self.param['machine_id'])

        try:
            ret_val, response = self._make_rest_call(url)
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        self.debug_print(f"{self.action_id} response:\n{json.dumps(response, indent=4)}")

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_machine_actions(self) -> object:
        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        url = f"{self.api_uri}{MACHINE_LIST_ACTIONS}".format(machine_id=self.param['machine_id'])

        try:
            ret_val, response = self._make_rest_call(url)
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        self.debug_print(f"{self.action_id} response:\n{json.dumps(response, indent=4)}")

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _handle_isolate_machine(self) -> object:
        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        url = f"{self.api_uri}{MACHINE_ISOLATE}".format(machine_id=self.param['machine_id'])

        try:
            ret_val, response = self._make_rest_call(url)
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        self.debug_print(f"{self.action_id} response:\n{json.dumps(response, indent=4)}")

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unisolate_machine(self) -> object:
        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        url = f"{self.api_uri}{MACHINE_UNISOLATE}".format(machine_id=self.param['machine_id'])

        try:
            ret_val, response = self._make_rest_call(url)
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        self.debug_print(f"{self.action_id} response:\n{json.dumps(response, indent=4)}")

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_file_info(self) -> object:
        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        url = f"{self.api_uri}{FILE_INFO}".format(file_id=self.param['file_id'])

        try:
            ret_val, response = self._make_rest_call(url)
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        self.debug_print(f"{self.action_id} response:\n{json.dumps(response, indent=4)}")

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_file_stats(self) -> object:
        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        url = f"{self.api_uri}{FILE_STATS}".format(file_id=self.param['file_id'])

        try:
            ret_val, response = self._make_rest_call(url)
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        self.debug_print(f"{self.action_id} response:\n{json.dumps(response, indent=4)}")

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _handle_quarantine_file(self) -> object:
        try:
            ret_val, r_json = self._authenticate()
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        url = f"{self.api_uri}{FILE_QUARANTINE}".format(machine_id=self.param['machine_id'])

        try:
            ret_val, response = self._make_rest_call(url)
        except Exception as e:
            message = self._get_error_message_from_exception(e, self.line_no)
            return RetVal(val1=self.action_result.set_status(phantom.APP_ERROR, message))

        if phantom.is_fail(ret_val):
            self.save_progress(self.action_result.get_message())
            return self.action_result.get_status()

        self.debug_print(f"{self.action_id} response:\n{json.dumps(response, indent=4)}")

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        self.param = param
        try:
            self.debug_print(f"Starting action: {self.action_id}")
            self.debug_print(f"Action parameters: {json.dumps(self.param, indent=4)}")
            ret_val = getattr(self, f"_handle_{self.action_id}")()
        except Exception as e:
            self.debug_print(self._get_error_message_from_exception(e, self.line_no))
            ret_val = phantom.APP_ERROR

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data that needs to be accessed across actions
        self.load_state()
        self._state = {key: val for key, val in self.get_state().items() if key in ['app_version', 'tokens']}

        if not self._state.get('tokens', False):
            self._state['tokens'] = {}

        for resource, token in self._state['tokens'].items():
            if resource not in self.resources:
                continue
            t = str(encryption_helper.decrypt(str(token['token']), self.asset_id))
            self.tokens[resource] = AuthenticationToken(token=t, expires_on=token['expires_on'])

        self.debug_print(f"Successfully loaded tokens:\n{json.dumps(self._parse_tokens(), indent=4)}")

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save any current tokens
        self._state['tokens'] = {
            r: {'token': encryption_helper.encrypt(str(t.token), self.asset_id), 'expires_on': t.expires_on}
            for r, t in self.tokens.items() if r in self.resources
        }

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
            r = phantom.requests.get(login_url, verify=verify, timeout=30)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={}'.format(csrftoken)
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = phantom.requests.post(login_url, verify=verify, data=data, headers=headers, timeout=30)
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
