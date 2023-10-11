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
import uuid, random
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
        self.live_response = {}
        self._action_start_time = datetime.datetime.now()
        self._rd = random.Random()

        # Input validation helper variables
        self.statuses = {
            'incident': {
                "Active": "Active",
                "Resolved": "Resolved",
                "Redirected": "Redirected",
                "default": False
            },
            'alert': {
                "New": "New",
                "In Progress": "InProgress",
                "Resolved": "Resolved",
                "default": False
            }
        }



        self.categories = {
            "None (removes current classification and determination)": ["", ""],
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
        return self.save_progstat(phantom.APP_ERROR, status_message=message)

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
            return self.save_progstat(phantom.APP_ERROR, status_message=message)

        # We have a successful response, albeit a redirect is possible...
        if 200 <= self.response.status_code < 400:
            message = f"Status code {self.response.status_code} received and JSON response parsed"
            return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

        # There's a generic error in our midst
        message = (
            f"!!! {str(self.r_json.get('error', {}).get('code', 'Unknown'))} error occurred [{self.response.status_code}]:"
            f"{str(self.r_json.get('error', {}).get('message', 'No message available'))}"
        )
        return self.save_progstat(phantom.APP_ERROR, status_message=message)

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
        return self.save_progstat(phantom.APP_ERROR, status_message=message)

    def _process_empty_response(self) -> bool:
        """
        This function is used to process empty response.
        :param response: response data
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if self.response.status_code in [200, 204]:
            return self.save_progstat(phantom.APP_SUCCESS)

        message = f"Status Code: {self.response.status_code}. Error: Empty response and no information in the header"
        return self.save_progstat(phantom.APP_ERROR, status_message=message)

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
                        method: str = "get", verify: bool = True, timeout: int = 30) -> bool:
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
            return self.save_progstat(phantom.APP_ERROR, status_message=message)

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
                                                              params=params, timeout=timeout)
        except Exception as e:
            message = f"Exception occurred while connecting to server: {self._get_exception_message(e, self.line_no)}"
            return self.save_progstat(phantom.APP_ERROR, status_message=message, exception=e)

        if 429 == self.response.status_code and 300 < int(self.response.headers.get('Retry-After', 301)):
            message = f"Error occurred [{self.response.status_code}]: {str(self.response.text)}"
            return self.save_progstat(phantom.APP_ERROR, status_message=message)

        if 429 == self.response.status_code and 300 >= int(self.response.headers.get('Retry-After', 301)):
            self.save_progress(f"Retrying after {self.response.headers.get('Retry-After', 301)} seconds")
            time.sleep(int(self.response.headers['Retry-After']) + 1)
            return self._make_rest_call(endpoint, headers=headers, params=params, data=data, method=method,
                                        verify=verify, timeout=timeout)

        return self._process_response()

    def _authenticate(self, resource: str) -> bool:
        # Instantiate new AuthenticationToken object as needed
        if not self.tokens.get(resource, False):
            self.tokens[resource] = AuthenticationToken(token="", expires_on=0)

        # AuthenticationToken allocated has not yet expired
        if self.tokens[resource].token:
            summary = self.tokens[resource].summary()
            message = f"Authentication for {resource} valid until {summary['expires_on']} ({summary['expires_in']})"
            return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

        # Prepare to request a new token
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
            return self.save_progstat(phantom.APP_ERROR, status_message=message)

        if 200 != self.response.status_code:
            message = f"Failed to authenticate [{self.r_json['error']}]: {self.r_json['error_description']}"
            return self.save_progstat(phantom.APP_ERROR, status_message=message)

        token = str(self.r_json.get('access_token', ''))
        expires_on = int(self.r_json.get('expires_on', 0))
        self.tokens[resource].update(token=token, expires_on=expires_on)

        summary = self.tokens[resource].summary()
        message = f"Authentication successful for {resource}: expires on {summary['expires_on']} ({summary['expires_in']})"
        self.save_progress(message)
        return self.action_result.set_status(phantom.APP_SUCCESS, status_message=message)

    def _handle_test_connectivity(self) -> bool:
        """
        Tests connection by attempting to authenticate to API

        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        if self.param.get("force_refresh", False):
            self.tokens = {}

        for resource in self.resources:
            self._authenticate(resource=resource)

        [self.action_result.add_data(token.summary()) for t, token in self.tokens.items()]

        tokens = {resource: token.summary() for resource, token in self.tokens.items() if 0 < token.expires_on}
        self.save_progress(f"Active access tokens:\n{json.dumps(tokens, indent=4)}")
        return self.action_result.set_status(phantom.APP_SUCCESS, status_message="Test complete")

    def _handle_list_incidents(self) -> bool:
        params = {f"${k}": v for k, v in self.param.items() if v and k in ['filter', 'top', 'skip']}
        param_set = []

        if not params.get("$skip", False):
            params["$skip"] = 0

        target = params["$top"] * 1
        params["$top"] = min(params["$top"], LIST_INCIDENTS_LIMIT)

        param_set = []

        while params["$skip"] < target:
            param_set.append({k: v for k, v in params.items()})
            params["$skip"] += min(LIST_INCIDENTS_LIMIT, target - params["$skip"])
            if target < LIST_INCIDENTS_LIMIT + params["$skip"]:
                params["$top"] = target % LIST_INCIDENTS_LIMIT
            else:
                params["$top"] = LIST_INCIDENTS_LIMIT

        url = f"{self.api_uri}{INCIDENT_LIST}".format(resource='security')
        incident_count = 0

        for param in param_set:
            if not self._make_rest_call(url, params=param, method="get"):
                return phantom.APP_ERROR

            for incident in self.r_json['value']:
                incident["source_data_identifier"] = self._sdi(incident["incidentId"])
                for i, alert in enumerate(incident["alerts"]):
                    incident["alerts"][i]["source_data_identifier"] = self._sdi(alert["alertId"])
                self.action_result.add_data(incident)

            incident_count += len(self.r_json.get("value", []))

        message = f"Returned {incident_count} incidents"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_incident(self) -> bool:
        url = f"{self.api_uri}{INCIDENT_SINGLE}".format(resource='security',
                                                        incident_id=self.param['incident_id'])

        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        self.r_json["source_data_identifier"] = self._sdi(self.r_json["incidentId"])

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"Retrieved incident {self.param['incident_id']}"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_update_incident(self) -> bool:
        if not self.param.get("remove_tags", False):
            url = f"{self.api_uri}{INCIDENT_SINGLE}".format(resource='security',
                                                            incident_id=self.param['incident_id'])

            if not self._make_rest_call(url, method="get"):
                return phantom.APP_ERROR

            self.param["tags"] = str(self.param.get("tags", "") + f",{','.join(self.r_json['tags'])}").strip(",")
            self.save_progress(f"Joined new tags with existing tags: '{self.param['tags']}'")

        body = {
            'status': self.statuses['incident'].get(self.param.get("status", "default"), False),
            'assignedTo': self.param.get("assigned_to", False),
            'classification': self.categories.get(self.param.get("category", False), [False])[0],
            # DOESN'T LIKE:
            # - InformationalExpectedActivity.ConfirmedUserActivity
            # - FalsePositive.Clean
            # - FalsePositive.InsufficientData
            # - TruePositive.CompromisedUser
            'determination': self.categories.get(self.param.get("category", False), [None, False])[1],
            'tags': [tag.strip() for tag in self.param.get("tags", "").split(",") if tag.strip()],
            'comment': self.param.get("comment", False)
        }
        body = {key: val for key, val in body.items() if val and "" != f"{val}"}
        data = json.dumps(body)

        # !! InvalidRequestBody error occurred [400]:Request body is incorrect

        url = f"{self.api_uri}{INCIDENT_SINGLE}".format(resource='security',
                                                        incident_id=self.param['incident_id'])

        if not self._make_rest_call(url, data=data, method="patch"):
            return phantom.APP_ERROR

        self.r_json["source_data_identifier"] = self._sdi(self.r_json["incidentId"])

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"Updated incident: {self.param['incident_id']}:\n{self.r_json}"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_alerts(self) -> bool:
        params = {f"${k}": v for k, v in self.param.items() if v and k in ['filter', 'top', 'skip']}

        if not params.get("$skip", False):
            params["$skip"] = 0

        target = params["$top"] * 1
        params["$top"] = min(params["$top"], LIST_ALERTS_LIMIT)

        param_set = []

        while params["$skip"] < target:
            param_set.append({k: v for k, v in params.items()})
            params["$skip"] += min(LIST_ALERTS_LIMIT, target - params["$skip"])
            if target < LIST_ALERTS_LIMIT + params["$skip"]:
                params["$top"] = target % LIST_ALERTS_LIMIT
            else:
                params["$top"] = LIST_ALERTS_LIMIT

        url = f"{self.api_uri}{ALERT_LIST}".format(resource='securitycenter')
        alert_count = 0

        if not self._make_rest_call(url, params=params, method="get"):
            return phantom.APP_ERROR

        for param in param_set:
            if not self._make_rest_call(url, params=param, method="get"):
                return phantom.APP_ERROR

            for alert in self.r_json['value']:
                alert["source_data_identifier"] = self._sdi(alert["id"])
                self.action_result.add_data(alert)

            alert_count += len(self.r_json.get("value", []))

        message = f"Returned {alert} alerts"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_alert(self) -> bool:
        url = f"{self.api_uri}{ALERT_SINGLE}".format(resource='securitycenter',
                                                     alert_id=self.param['alert_id'])

        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        self.r_json["alertId"] = self.r_json["id"]
        self.r_json["source_data_identifier"] = self._sdi(self.r_json["alertId"])
        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"Retrieved alert {self.param['alert_id']}"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_update_alert(self) -> bool:
        url = f"{self.api_uri}{ALERT_SINGLE}".format(resource='securitycenter', alert_id=self.param['alert_id'])

        body = {
            'status': self.statuses['alert'].get(self.param.get("status", "default"), False),
            'assignedTo': self.param.get("assigned_to", False),
            'classification': self.categories.get(self.param.get("category", False), [False])[0],
            # DOESN'T LIKE:
            # - InformationalExpectedActivity.ConfirmedUserActivity
            # - FalsePositive.Clean
            # - FalsePositive.InsufficientData
            # - TruePositive.CompromisedUser
            'determination': self.categories.get(self.param.get("category", False), [None, False])[1],
            'comment': self.param.get("comment", False)
        }
        body = {key: val for key, val in body.items() if val or "" == f"{val}"}
        data = json.dumps(body)

        # !! InvalidRequestBody error occurred [400]:Request body is incorrect

        if not self._make_rest_call(url, data=data, method="patch"):
            return phantom.APP_ERROR

        response = {
            'status': self.r_json.get("status", False),
            'assignedTo': self.r_json.get("assignedTo", False),
            'classification': self.r_json.get("classification", False),
            'determination': self.r_json.get("determination", False),
            'comment': self.r_json.get("comments", [{}])[-1].get("comment", False)
        }

        updates = {}
        for key, val in response.items():
            if not val or not body.get(key, False): continue
            updates[key] = "failed" if not body[key] == val else "success"

        message = f"Updated alert {self.param['alert_id']}:\n{json.dumps(updates, indent=4)}"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_update_alert_batch(self) -> bool:
        url = f"{self.api_uri}{ALERT_BATCH_UPDATE}".format(resource='securitycenter')

        body = {
            'alertIds': [alert_id.strip() for alert_id in ",".split(self.param['alert_list'])],
            'status': self.param.get("status", False),
            'assignedTo': self.param.get("assigned_to", False),
            'classification': self.categories.get(self.param.get("category", False), [False])[0],
            'determination': self.categories.get(self.param.get("category", False), [None, False])[1],
            'comment': self.param.get("comment", False)
        }
        data = json.dumps({key: val for key, val in body.items() if val})
        if not self._make_rest_call(url, data=data):
            return phantom.APP_ERROR

        message = f"Updated {len(self.param['alert_list'])} alerts:\n{json.dumps(self.r_json, indent=4)}"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_alert_files(self) -> bool:
        url = f"{self.api_uri}{ALERT_FILES}".format(resource='securitycenter',
                                                    alert_id=self.param["alert_id"])

        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        [self.action_result.add_data(file) for file in self.r_json['value']]

        message = f"Returned {len(self.r_json['value'])} files for alert {self.param['alert_id']}"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_library_scripts(self) -> bool:
        url = f"{self.api_uri}{LIVE_RESPONSE_LIST_LIBRARY}".format(resource='securitycenter')
        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        [self.action_result.add_data(script) for script in self.r_json['value']]

        message = f"Returned {len(self.r_json['value'])} scripts"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_run_actions(self) -> bool:
        url = f"{self.api_uri}{LIVE_RESPONSE_RUN_ACTION}".format(resource='securitycenter',
                                                                 machine_id=self.param['machine_id'])
        commands = []
        for command in self.param.get("commands", "").split("\n"):
            command_type, command_content = command.strip().split(sep=" ", maxsplit=1)
            if "putfile" == command_type.lower():
                commands.append({
                    "type": "PutFile",
                    "params": [{"key": "FileName", "value": command_content}]
                })
            if "runscript" == command_type.lower():
                commands.append({
                    "type": "RunScript",
                    "params": [
                        {"key": "ScriptName", "value": command_content.split(sep=" ", maxsplit=1)[0].strip()},
                        {"key": "Args", "value": command_content.split(sep=" ", maxsplit=1)[1].strip()}
                    ]
                })
            if "getfile" == command_type.lower():
                commands.append({
                    "type": "GetFile",
                    "params": [{"key": "Path", "value": command_content}]
                })

        if not commands:
            message = f"No valid commands found in {self.param.get('commands', '')}"
            return self.save_progstat(phantom.APP_ERROR, status_message=message)

        body = {
            'comment': self.param.get("comment", False),
            'commands': commands
        }
        data = json.dumps({key: val for key, val in body.items() if val})

        if not self._make_rest_call(url, data=data, method="post"):
            return phantom.APP_ERROR

        message = f"Commands sent to '{self.param['machine_id']}':\n{json.dumps(self.r_json, indent=4)}"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_run_action(self) -> bool:
        url = f"{self.api_uri}{LIVE_RESPONSE_RUN_ACTION}".format(resource='securitycenter',
                                                                 machine_id=self.param['machine_id'])

        params = None
        if "PutFile" == self.param.get("command_type", False):
            params = [{"key": "FileName", "value": self.param.get("file_name", False)}]
        if "RunScript" == self.param.get("command_type", False):
            params = [
                {"key": "ScriptName", "value": self.param.get("file_name", "")},
                {"key": "Args", "value": self.param.get("arguments", "")}
            ]
        if "GetFile" == self.param.get("command_type", False):
            params = [{"key": "Path", "value": self.param.get("file_name", False)}]

        if not params:
            message = f"You somehow managed to input an invalid command:\n{json.dumps(self.param, indent=4)}"
            return self.save_progstat(phantom.APP_ERROR, status_message=message)

        body = {
            'Commands': [{"type": self.param["command_type"], "params": params}],
            'Comment': self.param.get("comment", False)
        }
        data = json.dumps({key: val for key, val in body.items() if val})

        if not self._make_rest_call(url, data=data, method="post"):
            return phantom.APP_ERROR

        message = f"Command sent to '{self.param['machine_id']}':\n{json.dumps(self.r_json, indent=4)}"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_actions(self) -> bool:
        params = {f"${k}": v for k, v in self.param.items() if v and k in ['filter', 'top', 'skip']}
        url = f"{self.api_uri}{LIVE_RESPONSE_ACTIONS}".format(resource="securitycenter")

        if not self._make_rest_call(url, params=params, method="get", timeout=120):
            return phantom.APP_ERROR

        [self.action_result.add_data(action) for action in self.r_json['value']]

        message = f"Returned {len(self.r_json['value'])} actions"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_action(self) -> bool:
        url = f"{self.api_uri}{LIVE_RESPONSE_ACTION}".format(resource="securitycenter",
                                                             action_id=self.param['action_id'])
        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"{self.action_id} complete"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_action_result(self) -> object:
        url = f"{self.api_uri}{LIVE_RESPONSE_ACTION_RESULT}".format(resource="securitycenter",
                                                                    action_id=self.param['action_id'],
                                                                    command_index=self.param['command_index'])

        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"{self.action_id} complete"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_investigations(self) -> object:
        params = {f"${k}": v for k, v in self.param.items() if v and k in ['filter', 'top', 'skip']}
        url = f"{self.api_uri}{INVESTIGATION_LIST}".format(resource="securitycenter")

        if not self._make_rest_call(url, params=params, method="get"):
            return phantom.APP_ERROR

        [self.action_result.add_data(action) for action in self.r_json['value']]

        message = f"{self.action_id} complete"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_investigation(self) -> object:
        url = f"{self.api_uri}{INVESTIGATION_SINGLE}".format(resource='securitycenter',
                                                             investigation_id=self.param['investigation_id'])

        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"{self.action_id} complete"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_start_investigation(self) -> object:
        url = f"{self.api_uri}{INVESTIGATION_START}".format(resource='securitycenter',
                                                            machine_id=self.param['machine_id'])

        body = {
            'Comment': self.param.get("comment", False)
        }
        data = json.dumps({key: val for key, val in body.items() if val})

        if not self._make_rest_call(url, data=data, method="post"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"{self.action_id} complete"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_collect_investigation_package(self) -> object:
        url = f"{self.api_uri}{INVESTIGATION_COLLECT_PACKAGE}".format(resource='securitycenter',
                                                                      machine_id=self.param['machine_id'])

        body = {
            'Comment': self.param.get("comment", False)
        }
        data = json.dumps({key: val for key, val in body.items() if val})

        if not self._make_rest_call(url, data=data, method="post"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"{self.action_id} complete"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_machine_actions(self) -> object:
        params = {f"${k}": v for k, v in self.param.items() if v and k in ['filter', 'top', 'skip']}
        url = f"{self.api_uri}{MACHINE_LIST_ACTIONS}".format(resource='securitycenter',
                                                             machine_id=self.param['machine_id'])

        if not self._make_rest_call(url, params=params, method="get"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"{self.action_id} complete"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_isolate_machine(self) -> object:
        url = f"{self.api_uri}{MACHINE_ISOLATE}".format(resource='securitycenter',
                                                        machine_id=self.param['machine_id'])

        if not self._make_rest_call(url, method="post"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"{self.action_id} complete"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_unisolate_machine(self) -> object:
        url = f"{self.api_uri}{MACHINE_UNISOLATE}".format(resource='securitycenter',
                                                          machine_id=self.param['machine_id'])

        if not self._make_rest_call(url, method="post"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"{self.action_id} complete"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_file_info(self) -> object:
        url = f"{self.api_uri}{FILE_INFO}".format(file_id=self.param['file_hash'])

        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"{self.action_id} complete"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_file_stats(self) -> object:
        url = f"{self.api_uri}{FILE_STATS}".format(file_id=self.param['file_id'])

        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"{self.action_id} complete"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_quarantine_file(self) -> object:
        url = f"{self.api_uri}{FILE_QUARANTINE}".format(machine_id=self.param['machine_id'])

        if not self._make_rest_call(url, method="post"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"{self.action_id} complete"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def _handle_widget_update(self) -> bool:
        url = f"{self.api_uri}{INCIDENT_SINGLE}".format(resource='security',
                                                        incident_id=self.param['incident_id'])

        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        self.r_json["source_data_identifier"] = self._sdi(self.r_json["incidentId"])

        uri_prefix = rp.split("incident", self.r_json["incidentUri"])[0]
        alert_links = {"alert_link": f"{uri_prefix}alerts/{alert['alertId']}" for alert in self.r_json["alerts"]}

        self.action_result.add_data(alert_links)

        message = f"Updated widget for {self.param['incident_id']}"
        return self.save_progstat(phantom.APP_SUCCESS, status_message=message)

    def handle_action(self, param) -> bool:
        self.param = param
        self.save_progress(f"Starting action: {self.action_id}\n{json.dumps(self.param, indent=4)}")

        if not getattr(self, f"_handle_{self.action_id}")() and self.r_json:
            self.save_progstat(phantom.APP_ERROR, f"{self.action_id} has no _handler function")

        return self.get_status()

    def save_progstat(self, status_code: bool, status_message: str = None) -> bool:
        self.save_progress(progress_str_const=status_message)
        return self.action_result.set_status(status_code=status_code, status_message=status_message)

    def _sdi(self, input: str) -> str:
        self._rd.seed(input)
        return str(uuid.UUID(version=4, int=self._rd.getrandbits(128)))

    def initialize(self):
        # Load the state in initialize, use it to store data that needs to be accessed across actions
        self.load_state()
        self._state = {key: val for key, val in self.get_state().items()}

        if not self._state.get('tokens', False):
            self._state['tokens'] = {}

        if not self._state.get('live_response', False):
            self._state['live_response'] = {}

        if not self._state.get('isolated_devices', False):
            self._state['isolated_devices'] = []

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

        # Save any active live response actions
        self._state['live_response'] = {k: v for k, v in self.live_response.items()}

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        self.save_progress(f"Action execution time: {datetime.datetime.now() - self._action_start_time} seconds")
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
