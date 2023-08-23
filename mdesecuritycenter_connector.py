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

# If you find errors or would like to help contribute, please see:
# https://github.com/supergnaw/phMDE-Security-Center
#
# For more info regarding the mysterious functions and libraries within this code, please see:
# https://docs.splunk.com/Documentation/SOARonprem/latest/DevelopApps/AppDevAPIRef

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
        self.response = None
        self.r_json = None

        # Input validation helper variables
        self.statuses = {
            "Active": "Active",
            "Resolved": "Resolved",
            "Redirected": "Redirected",
            "default": False
        }

        self.categories = {
            "Informational: Security test": ["InformationalExpectedActivity", "SecurityTesting"],
            "Informational: Line-of-business application": ["InformationalExpectedActivity",
                                                            "LineOfBusinessApplication"],
            "Informational: Confirmed activity": ["InformationalExpectedActivity", "ConfirmedUserActivity"],
            "Informational: Other": ["InformationalExpectedActivity", "Other"],
            "False positive: Not malicious": ["FalsePositive", "Clean"],
            "False positive: Not enough data to validate": ["FalsePositive", "InsufficientData"],
            "False positive: Other": ["FalsePositive", "Other"],
            "True positive: Multistage attack": ["TruePositive", "MultiStagedAttack"],
            "True positive: Malicious user activity": ["TruePositive", "MaliciousUserActivity"],
            "True positive: Compromised account": ["TruePositive", "CompromisedUser"],
            "True positive: Malware": ["TruePositive", "Malware"],
            "True positive: Phishing": ["TruePositive", "Phishing"],
            "True positive: Unwanted software": ["TruePositive", "UnwantedSoftware"],
            "True positive: Other": ["TruePositive", "Other"],
        }

    def _process_response(self) -> bool:
        """
        This function is used to process html response.
        :param response: response data
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        self.action_result.add_debug_data({'r_status_code': self.response.status_code})
        self.action_result.add_debug_data({'r_text': self.response.text})
        self.action_result.add_debug_data({'r_headers': self.response.headers})

        if 'application/json' in self.response.headers.get('Content-Type', '').lower():
            return self._process_json_response()

        if 'text/html' in self.response.headers.get('Content-Type', '').lower():
            return self._process_html_response()

        if not self.response.text:
            return self._process_empty_response()

        message = f"Can't process response from server [{self.response.status_code}]: {self.response}"
        return self.set_status_save_progress(phantom.APP_ERROR, status_message=message)

    def _process_json_response(self) -> bool:
        """
        This function is used to process json response.
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        # Parse! That!! JSON!!! (with enthusiasm!!!!)
        try:
            self.r_json = self.response.json()
        except Exception as e:
            message = f"Unable to parse JSON response: {self._get_exception_message(e, self.line_no)}"
            return self.set_status_save_progress(phantom.APP_ERROR, status_message=message)

        # We have a successful response, albeit a redirect is possible...
        if 200 <= self.response.status_code < 400:
            message = f"Status code {self.response.status_code} received and JSON response parsed"
            self.save_progress(message)
            return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

        # There's a generic error in our midst
        message = (
            f"!!! {str(self.r_json.get('error', {}).get('code', 'Unknown'))} error occurred [{self.response.status_code}]:"
            f"{str(self.r_json.get('error', {}).get('message', 'No message available'))}"
        )
        return self.set_status_save_progress(phantom.APP_ERROR, status_message=message)

    def _process_html_response(self) -> bool:
        """
        This function is used to process html response.
        :param response: response data
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        try:
            # Remove extra elements
            content = rp.sub(
                repl="", string=self.response.text, pattern=(
                    "/(<script.*?(?=<\/script>)<\/script>|<style.*?(?=<\/style>)<\/style>|"
                    "<footer.*?(?=<\/footer>)<\/footer>|<nav.*?(?=<\/nav>)<\/nav>)/sim"
                )
            )
            # Clear out extra whitespace and empty lines
            error_text = rp.sub(pattern="/\s+/sim", repl=" ", string=content).strip()
        except Exception:
            error_text = "Cannot parse error details"

        if not error_text:
            error_text = "Error message unavailable. Please check the asset configuration and/or the action parameters"

        # Use f-strings, we are not uncivilized heathens.
        message = f"Status Code: {self.response.status_code}. Raw data from server:\n{error_text}\n"

        return self.set_status_save_progress(phantom.APP_ERROR, status_message=message)

    def _process_empty_response(self) -> bool:
        """
        This function is used to process empty response.
        :param response: response data
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if self.response.status_code in [200, 204]:
            return self.set_status_save_progress(phantom.APP_SUCCESS)

        message = f"Status Code: {self.response.status_code}. Error: Empty response and no information in the header"
        return self.set_status_save_progress(phantom.APP_ERROR, status_message=message)

    def _get_exception_message(self, e: Exception, line_no: int = 0) -> str:
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

        self.action_result.add_debug_data({'exception debug message': debug_message})

        return debug_message

    def _make_rest_call(self, endpoint: str, headers: dict = {}, params: dict = {}, data: dict or str = None,
                        method: str = "get", verify: bool = True) -> bool:
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
            return self.set_status_save_progress(phantom.APP_ERROR, status_message=message)

        resource = rp.search(pattern="/\.([^\.]+)\.microsoft/i", string=endpoint).group(1)
        if not self._authenticate(resource=resource):
            return phantom.APP_ERROR

        # Global headers verification
        if not headers.get('Content-Type', False):
            headers["Content-Type"] = "application/json"
        if not headers.get('Authorization', False):
            headers["Authorization"] = f"Bearer {self.tokens[resource].token}"
        if not headers.get('Accept', False):
            headers["Accept"] = "application/json"

        self.action_result.add_debug_data({
            '_make_rest_call endpoint': endpoint,
            '_make_rest_call method': method,
            '_make_rest_call headers': headers,
            '_make_rest_call data': data
        })

        if isinstance(data, dict):
            data = json.dumps(data)

        self.save_progress(f"Attempting {method.upper()} request to: {endpoint}")

        try:
            self.response = getattr(phantom.requests, method)(endpoint, data=data, headers=headers, verify=verify,
                                                              params=params, timeout=30)
        except Exception as e:
            message = f"Exception occurred while connecting to server: {self._get_exception_message(e, self.line_no)}"
            return self.set_status_save_progress(phantom.APP_ERROR, status_message=message, exception=e)

        if 429 == self.response.status_code and 300 < int(self.response.headers.get('Retry-After', 301)):
            message = f"Error occurred [{self.response.status_code}]: {str(self.response.text)}"
            return self.set_status_save_progress(phantom.APP_ERROR, status_message=message)

        if 429 == self.response.status_code and 300 >= int(self.response.headers.get('Retry-After', 301)):
            self.save_progress(f"Retrying after {self.response.headers.get('Retry-After', 301)} seconds")
            time.sleep(int(self.response.headers['Retry-After']) + 1)
            return self._make_rest_call(endpoint, headers=headers, params=params, data=data, method=method,
                                        verify=verify)

        return self._process_response()

    def _authenticate(self, resource: str) -> bool:
        # Instantiate new AuthenticationToken object if not exists
        if not self.tokens.get(resource, False):
            self.tokens[resource] = AuthenticationToken(token="", expires_on=0)

        # Resource already has a token allocated which has not yet expired
        if self.tokens[resource].token:
            summary = self.tokens[resource].summary()
            message = f"Authentication for {resource} valid until {summary['expires_on']} ({summary['expires_in']})"
            return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

        # Request properties
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        body = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'resource': self.api_uri.format(resource=resource),
            'grant_type': 'client_credentials'
        }
        url = f"{self.login_uri}/{self.tenant_id}/oauth2/token"
        data = urllib.parse.urlencode(body).encode("utf-8")

        # The authentication request is a bit different from other REST calls so let's make a special one!
        try:
            self.response = phantom.requests.get(url, data=data, headers=headers)
            self.r_json = self.response.json()
        except Exception as e:
            message = self._get_exception_message(e, (self.line_no - 3))
            return self.set_status_save_progress(phantom.APP_ERROR, status_message=message)

        if 200 != self.response.status_code:
            message = f"Failed to authenticate [{self.r_json['error']}]: {self.r_json['error_description']}"
            return self.set_status_save_progress(phantom.APP_ERROR, status_message=message)

        token = str(self.r_json.get('access_token', ''))
        expires_on = int(self.r_json.get('expires_on', 0))
        self.tokens[resource].update(token=token, expires_on=expires_on)

        summary = self.tokens[resource].summary()
        message = f"Authentication successful for {resource}: expires {summary['expires_on']} ({summary['expires_in']})"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _parse_tokens(self) -> dict:
        # Return a dictionary of "active" authentication tokens and a summary of their details
        return {resource: token.summary() for resource, token in self.tokens.items() if 0 < token.expires_on}

    def _handle_test_connectivity(self) -> bool:
        """
        Tests connection by attempting to authenticate to API

        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        for resource in self.resources:
            self._authenticate(resource=resource)

        message = f"Active access tokens:\n{json.dumps(self._parse_tokens(), indent=4)}"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_incidents(self) -> bool:
        params = {f"${k}": v for k, v in self.param.items() if v and k in ['filter', 'top', 'skip']}
        url = f"{self.api_uri}{INCIDENT_LIST}".format(resource='security')
        if not self._make_rest_call(endpoint=url, params=params):
            return phantom.APP_ERROR

        [self.add_data(incident) for incident in self.r_json['value']]

        message = f"Returned {len(self.r_json['value'])} incidents"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_incident(self) -> bool:
        url = f"{self.api_uri}{INCIDENT_SINGLE}".format(resource='security', incident_id=self.param['incident_id'])
        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        self.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"Retrieved incident {self.param['incident_id']}"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_update_incident(self) -> bool:
        if self.param.get("remove_tags", False):
            url = f"{self.api_uri}{INCIDENT_SINGLE}".format(resource='security', incident_id=self.param['incident_id'])
            if not self._make_rest_call(url, method="get"):
                return phantom.APP_ERROR

            self.param["tags"] = str(self.param.get("tags", "") + f",{','.join(self.r_json['tags'])}").strip(",")
            self.save_progress(f"Joined new tags with existing tags: '{self.param['tags']}'")

        body = {
            'status': self.statuses.get(self.param.get("status", "default"), False),
            'assignedTo': self.param.get("assigned_to", False),
            'classification': self.categories.get(self.param.get("category", False), [False])[0],
            'determination': self.categories.get(self.param.get("category", False), [None, False])[1],
            'tags': [tag.strip() for tag in self.param.get("tags", "").split(",") if tag.strip()],
            'comment': self.param.get("comment", False)
        }
        data = json.dumps({key: val for key, val in body.items() if val})

        url = f"{self.api_uri}{INCIDENT_SINGLE}".format(resource='security', incident_id=self.param['incident_id'])
        if not self._make_rest_call(url, data=data, method="patch"):
            return phantom.APP_ERROR

        message = f"Updated incident {self.param['incident_id']}:\n{json.dumps(self.r_json, indent=4)}"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_alerts(self) -> bool:
        url = f"{self.api_uri}{ALERT_LIST}".format(resource='securitycenter')
        if not self._make_rest_call(url):
            return phantom.APP_ERROR

        [self.add_data(alert) for alert in self.r_json['value']]

        message = f"Returned {len(self.r_json['value'])} alerts"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_alert(self) -> bool:
        url = f"{self.api_uri}{ALERT_SINGLE}".format(resource='securitycenter', alert_id=self.param['alert_id'])
        if not self._make_rest_call(url):
            return phantom.APP_ERROR

        self.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"Retrieved alert {self.param['alert_id']}"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_update_alert(self) -> bool:
        body = {
            'status': self.statuses.get(self.param.get("status", "default"), False),
            'assignedTo': self.param.get("assigned_to", False),
            'classification': self.categories.get(self.param.get("category", False), [False])[0],
            'determination': self.categories.get(self.param.get("category", False), [None, False])[1],
            'comment': self.param.get("comment", False)
        }
        data = json.dumps({key: val for key, val in body.items() if val})

        url = f"{self.api_uri}{ALERT_SINGLE}".format(resource='securitycenter', alert_id=self.param['alert_id'])
        if not self._make_rest_call(url, data=data):
            return phantom.APP_ERROR

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_update_alert_batch(self) -> object:
        url = f"{self.api_uri}{ALERT_BATCH_UPDATE}".format(resource='securitycenter')
        if not self._make_rest_call(url):
            return phantom.APP_ERROR

        self.debug_print(f"{self.action_id} response:\n{json.dumps(self.r_json, indent=4)}")

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_alert_files(self) -> object:
        url = f"{self.api_uri}{ALERT_FILES}".format(resource='securitycenter')
        if not self._make_rest_call(url):
            return phantom.APP_ERROR

        self.debug_print(f"{self.action_id} response:\n{json.dumps(self.r_json, indent=4)}")

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_library_scripts(self) -> object:
        url = f"{self.api_uri}{LIVE_RESPONSE_LIST_LIBRARY}".format(resource='securitycenter')
        if not self._make_rest_call(url):
            return phantom.APP_ERROR

        self.debug_print(f"{self.action_id} response:\n{json.dumps(self.r_json, indent=4)}")

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_run_library_script(self) -> object:
        url = f"{self.api_uri}{LIVE_RESPONSE_RUN_SCRIPT}".format(resource='securitycenter',
                                                                 machine_id=self.param['machine_id'])
        if not self._make_rest_call(url):
            return phantom.APP_ERROR

        self.debug_print(f"{self.action_id} response:\n{json.dumps(self.r_json, indent=4)}")

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_library_script_result(self) -> object:
        url = f"{self.api_uri}{LIVE_RESPONSE_GET_RESULT}".format(action_id=self.param['action_id'],
                                                                 command_index=self.param['command_index'])
        if not self._make_rest_call(url):
            return phantom.APP_ERROR

        self.debug_print(f"{self.action_id} response:\n{json.dumps(self.r_json, indent=4)}")

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_investigations(self) -> object:
        url = f"{self.api_uri}{INVESTIGATION_LIST}"
        if not self._make_rest_call(url):
            return phantom.APP_ERROR

        self.debug_print(f"{self.action_id} response:\n{json.dumps(self.r_json, indent=4)}")

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_investigation(self) -> object:
        url = f"{self.api_uri}{INVESTIGATION_SINGLE}".format(investigation_id=self.param['investigation_id'])
        if not self._make_rest_call(url):
            return phantom.APP_ERROR

        self.debug_print(f"{self.action_id} response:\n{json.dumps(self.r_json, indent=4)}")

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_start_investigation(self) -> object:
        url = f"{self.api_uri}{INVESTIGATION_START}".format(machine_id=self.param['machine_id'])
        if not self._make_rest_call(url):
            return phantom.APP_ERROR

        self.debug_print(f"{self.action_id} response:\n{json.dumps(self.r_json, indent=4)}")

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_collect_investigation_package(self) -> object:
        url = f"{self.api_uri}{INVESTIGATION_COLLECT_PACKAGE}".format(machine_id=self.param['machine_id'])
        if not self._make_rest_call(url):
            return phantom.APP_ERROR

        self.debug_print(f"{self.action_id} response:\n{json.dumps(self.r_json, indent=4)}")

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_machine_actions(self) -> object:
        url = f"{self.api_uri}{MACHINE_LIST_ACTIONS}".format(machine_id=self.param['machine_id'])
        if not self._make_rest_call(url):
            return phantom.APP_ERROR

        self.debug_print(f"{self.action_id} response:\n{json.dumps(self.r_json, indent=4)}")

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_isolate_machine(self) -> object:
        url = f"{self.api_uri}{MACHINE_ISOLATE}".format(machine_id=self.param['machine_id'])
        if not self._make_rest_call(url):
            return phantom.APP_ERROR

        self.debug_print(f"{self.action_id} response:\n{json.dumps(self.r_json, indent=4)}")

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_unisolate_machine(self) -> object:
        url = f"{self.api_uri}{MACHINE_UNISOLATE}".format(machine_id=self.param['machine_id'])
        if not self._make_rest_call(url):
            return phantom.APP_ERROR

        self.debug_print(f"{self.action_id} response:\n{json.dumps(self.r_json, indent=4)}")

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_file_info(self) -> object:
        url = f"{self.api_uri}{FILE_INFO}".format(file_id=self.param['file_id'])
        if not self._make_rest_call(url):
            return phantom.APP_ERROR

        self.debug_print(f"{self.action_id} response:\n{json.dumps(self.r_json, indent=4)}")

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_file_stats(self) -> object:
        url = f"{self.api_uri}{FILE_STATS}".format(file_id=self.param['file_id'])
        if not self._make_rest_call(url):
            return phantom.APP_ERROR

        self.debug_print(f"{self.action_id} response:\n{json.dumps(self.r_json, indent=4)}")

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_quarantine_file(self) -> object:
        url = f"{self.api_uri}{FILE_QUARANTINE}".format(machine_id=self.param['machine_id'])
        if not self._make_rest_call(url):
            return phantom.APP_ERROR

        self.debug_print(f"{self.action_id} response:\n{json.dumps(self.r_json, indent=4)}")

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def handle_action(self, param) -> bool:
        self.param = param
        self.save_progress(f"Starting action: {self.action_id}\n{json.dumps(self.param, indent=4)}")

        getattr(self, f"_handle_{self.action_id}")()

        return self.get_status()

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
