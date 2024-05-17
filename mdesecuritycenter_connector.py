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

import phantom.rules as phanrules
import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
import encryption_helper

import json
import time
from datetime import datetime, timezone, timedelta
import urllib
import base64
import hashlib, uuid, random
import replus as rp
from inspect import currentframe

from mdesecuritycenter_consts import *


class AuthenticationToken:
    def __init__(self, token: str, expires_on: int) -> None:
        self._token = ""
        self._expires_on = 0
        self._endpoint = ""
        self.update(token=token, expires_on=expires_on)
        self.debug_print = False

    @property
    def token(self) -> str or bool:
        # expired
        if int(datetime.now(timezone.utc).strftime("%s")) > self.expires_on - 60:
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

    def details(self) -> list:
        details = [json.loads(base64.b64decode(part + ('=' * (-len(part) % 4))).decode('utf-8')) for part
                   in self._token.split('.')[0:2]]
        return details

    def summary(self) -> dict:
        details = self.details()
        seconds = self.expires_on - int(datetime.now(timezone.utc).strftime("%s"))

        summary = {
            'endpoint': details[1]['aud'],
            'expires_in': f"{seconds // 60}m {seconds % 60}s",
            'expires_on': str(datetime.fromtimestamp(self.expires_on)),
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
    def ingest_window(self) -> int:
        return self.get_config().get("ingest_window", 24)

    @property
    def max_incidents(self) -> int:
        return self.get_config().get("max_incidents", 250)

    @property
    def filter_list(self) -> str:
        return self.get_config().get("filter_list", "MDE Security Center Ingest Filter")

    @property
    def field_map(self) -> dict:
        return json.loads(self.get_config().get("field_mapping", "{}"))

    @property
    def on_poll_behavior(self) -> str:
        return self.get_config().get("on_poll_behavior", "ingest")

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
    def cef(self) -> list:
        if 0 == len(self._cef):
            uri = phanrules.build_phantom_rest_url("cef") + "?page_size=0"
            response = phantom.requests.get(uri, verify=False)

            if 200 > response.status_code or 299 < response.status_code:
                return self._cef

            self._cef = [cef['name'] for cef in json.loads(response.text)['data']]
        return self._cef

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
        self._action_start_time = datetime.now()
        self._rd = random.Random()
        self._cef = []
        self.containers_to_save = []

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
            },
            'container': {
                "Active": "Open",
                "New": "New",
                "Resolved": "Closed",
                "default": "New"
            }
        }

        self.categories = {
            "None (removes current classification and determination)": ["", ""],
            "Informational: Security test": ["InformationalExpectedActivity", "SecurityTesting"],
            "Informational: Line-of-business application": ["InformationalExpectedActivity",
                                                            "LineOfBusinessApplication"],
            "Informational: Confirmed activity": ["InformationalExpectedActivity",
                                                  "ConfirmedUserActivity"],
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
            return self.set_status_save_progress(phantom.APP_ERROR, status_message=message)

        # resource = rp.search(pattern=r"/[^\w]([^\.]+)\.microsoft/i", string=endpoint).group(1)
        resource = rp.search(pattern=r"/[^\w]+([^\.]+)\.microsoft/i", string=endpoint).group(1)
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
            return self.set_status_save_progress(phantom.APP_ERROR, status_message=message, exception=e)

        if 429 == self.response.status_code and 300 < int(self.response.headers.get('Retry-After', 301)):
            message = f"Error occurred [{self.response.status_code}]: {str(self.response.text)}"
            return self.set_status_save_progress(phantom.APP_ERROR, status_message=message)

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
            return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

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
            return self.set_status_save_progress(phantom.APP_ERROR, status_message=message)

        if 200 != self.response.status_code:
            message = f"Failed to authenticate [{self.r_json['error']}]: {self.r_json['error_description']}"
            return self.set_status_save_progress(phantom.APP_ERROR, status_message=message)

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
                incident["source_data_identifier"] = self._sdi(incident)
                for i, alert in enumerate(incident["alerts"]):
                    incident["alerts"][i]["source_data_identifier"] = self._sdi(alert)
                self.action_result.add_data(incident)

            incident_count += len(self.r_json.get("value", []))

        message = f"Returned {incident_count} incidents"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_incident(self) -> bool:
        url = f"{self.api_uri}{INCIDENT_SINGLE}".format(resource='security',
                                                        incident_id=self.param['incident_id'])

        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        self.r_json["source_data_identifier"] = self._sdi(self.r_json)

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"Retrieved incident {self.param['incident_id']}"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_update_incident(self) -> bool:
        # get current container tags
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

        url = f"{self.api_uri}{INCIDENT_SINGLE}".format(resource='security',
                                                        incident_id=self.param['incident_id'])

        if not self._make_rest_call(url, data=data, method="patch"):
            return phantom.APP_ERROR

        self.r_json["source_data_identifier"] = self._sdi(self.r_json)

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"Updated incident: {self.param['incident_id']}:\n{self.r_json}"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_alerts(self) -> bool:
        params = {f"${k}": v for k, v in self.param.items() if v and k in ['filter', 'top', 'skip']}
        params["$expand"] = "evidence"

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
                alert["source_data_identifier"] = self._sdi(alert)
                self.action_result.add_data(alert)

            alert_count += len(self.r_json.get("value", []))

        message = f"Returned {alert} alerts"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_alert(self) -> bool:
        url = f"{self.api_uri}{ALERT_SINGLE}".format(resource='securitycenter',
                                                     alert_id=self.param['alert_id'])
        params = {"$expand": "evidence"}

        if not self._make_rest_call(url, params=params, method="get"):
            return phantom.APP_ERROR

        self.r_json["alertId"] = self.r_json["id"]
        self.r_json["source_data_identifier"] = self._sdi(self.r_json)
        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"Retrieved alert {self.param['alert_id']}"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

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
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

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
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_alert_files(self) -> bool:
        url = f"{self.api_uri}{ALERT_FILES}".format(resource='securitycenter',
                                                    alert_id=self.param["alert_id"])

        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        [self.action_result.add_data(file) for file in self.r_json['value']]

        message = f"Returned {len(self.r_json['value'])} files for alert {self.param['alert_id']}"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_library_scripts(self) -> bool:
        url = f"{self.api_uri}{LIVE_RESPONSE_LIST_LIBRARY}".format(resource='securitycenter')
        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        [self.action_result.add_data(script) for script in self.r_json['value']]

        message = f"Returned {len(self.r_json['value'])} scripts"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

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
            return self.set_status_save_progress(phantom.APP_ERROR, status_message=message)

        body = {
            'comment': self.param.get("comment", False),
            'commands': commands
        }
        data = json.dumps({key: val for key, val in body.items() if val})

        if not self._make_rest_call(url, data=data, method="post"):
            return phantom.APP_ERROR

        message = f"Commands sent to '{self.param['machine_id']}':\n{json.dumps(self.r_json, indent=4)}"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

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
            return self.set_status_save_progress(phantom.APP_ERROR, status_message=message)

        body = {
            'Commands': [{"type": self.param["command_type"], "params": params}],
            'Comment': self.param.get("comment", False)
        }
        data = json.dumps({key: val for key, val in body.items() if val})

        if not self._make_rest_call(url, data=data, method="post"):
            return phantom.APP_ERROR

        message = f"Command sent to '{self.param['machine_id']}':\n{json.dumps(self.r_json, indent=4)}"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_actions(self) -> bool:
        params = {f"${k}": v for k, v in self.param.items() if v and k in ['filter', 'top', 'skip']}
        url = f"{self.api_uri}{LIVE_RESPONSE_ACTIONS}".format(resource="securitycenter")

        if not self._make_rest_call(url, params=params, method="get", timeout=120):
            return phantom.APP_ERROR

        [self.action_result.add_data(action) for action in self.r_json['value']]

        message = f"Returned {len(self.r_json['value'])} actions"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_action(self) -> bool:
        url = f"{self.api_uri}{LIVE_RESPONSE_ACTION}".format(resource="securitycenter",
                                                             action_id=self.param['action_id'])
        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_action_result(self) -> object:
        url = f"{self.api_uri}{LIVE_RESPONSE_ACTION_RESULT}".format(resource="securitycenter",
                                                                    action_id=self.param['action_id'],
                                                                    command_index=self.param['command_index'])

        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_investigations(self) -> object:
        params = {f"${k}": v for k, v in self.param.items() if v and k in ['filter', 'top', 'skip']}
        url = f"{self.api_uri}{INVESTIGATION_LIST}".format(resource="securitycenter")

        if not self._make_rest_call(url, params=params, method="get"):
            return phantom.APP_ERROR

        [self.action_result.add_data(action) for action in self.r_json['value']]

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_investigation(self) -> object:
        url = f"{self.api_uri}{INVESTIGATION_SINGLE}".format(resource='securitycenter',
                                                             investigation_id=self.param['investigation_id'])

        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

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
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

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
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_machine_actions(self) -> object:
        params = {f"${k}": v for k, v in self.param.items() if v and k in ['filter', 'top', 'skip']}
        url = f"{self.api_uri}{MACHINE_LIST_ACTIONS}".format(resource='securitycenter',
                                                             machine_id=self.param['machine_id'])

        if not self._make_rest_call(url, params=params, method="get"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_isolate_machine(self) -> object:
        url = f"{self.api_uri}{MACHINE_ISOLATE}".format(resource='securitycenter',
                                                        machine_id=self.param['machine_id'])

        if not self._make_rest_call(url, method="post"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_unisolate_machine(self) -> object:
        url = f"{self.api_uri}{MACHINE_UNISOLATE}".format(resource='securitycenter',
                                                          machine_id=self.param['machine_id'])

        if not self._make_rest_call(url, method="post"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_file_info(self) -> object:
        url = f"{self.api_uri}{FILE_INFO}".format(file_id=self.param['file_hash'])

        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_file_stats(self) -> object:
        url = f"{self.api_uri}{FILE_STATS}".format(file_id=self.param['file_id'])

        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_quarantine_file(self) -> object:
        url = f"{self.api_uri}{FILE_QUARANTINE}".format(machine_id=self.param['machine_id'])

        if not self._make_rest_call(url, method="post"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"{self.action_id} complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_on_poll(self) -> bool:
        # generate timestamp for ingestion
        x_hours_ago = (datetime.utcnow() - timedelta(hours=self.ingest_window)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        container_label = self._get_asset_label()
        container_tags = self._get_asset_tags()

        # fetch the incidents
        url = f"{self.api_uri}{INCIDENT_LIST}".format(resource='security')
        incident_count = 0
        incidents = []
        target = self.max_incidents
        params = {
            "$filter": f"createdTime gt {x_hours_ago}",
            "$top": min(self.max_incidents, LIST_INCIDENTS_LIMIT),
            "$skip": 0
        }

        while params["$skip"] < target:
            if not self._make_rest_call(url, params=params, method="get"):
                return phantom.APP_ERROR

            for incident in self.r_json["value"]:
                incident["source_data_identifier"] = self._sdi(incident)

                for a, alert in enumerate(incident["alerts"]):
                    incident["alerts"][a]["source_data_identifier"] = self._sdi(alert)

                incidents.append(incident)
                incident_count += 1

            params["$skip"] = min(target, params["$skip"] + LIST_INCIDENTS_LIMIT)
            params["$top"] = min(target - params["$skip"], LIST_INCIDENTS_LIMIT)

        if 1 == incident_count:
            return_message = f"MDE returned {incident_count} incident"
        else:
            return_message = f"MDE returned {incident_count} incidents"

        # get filter list rules
        filter_list = self._get_filter_list()

        # search for any existing containers
        source_data_identifiers = []
        for incident in incidents:
            if incident['source_data_identifier']:
                source_data_identifiers.append(incident['source_data_identifier'])

        existing_containers = {}
        if source_data_identifiers:
            artifact_search_uris = []
            sdi_string = ""

            # split the long list of source data identifiers into smaller chunks for URI consumption
            chunk_size = 42
            sdi_chunks = [
                source_data_identifiers[i:i + chunk_size] for i in range(0, len(source_data_identifiers), chunk_size)]

            for chunk in sdi_chunks:
                query_string = '","'.join(chunk)
                search_uri = (f"{phanrules.build_phantom_rest_url('artifact')}"
                              f"?_filter_source_data_identifier__in=[\"{query_string}\"]")
                for container_data in phantom.requests.get(search_uri, verify=False).json().get("data", []):
                    existing_containers[container_data["source_data_identifier"]] = container_data

        # perform actions on incidents
        for incident in incidents:

            # if an action is taken, this is set to true to bypass the default on_poll behavior
            action_taken = False

            # update parity between SOAR and MDE
            existing_container = existing_containers.get(incident["source_data_identifier"], None)
            if existing_container:
                self.debug_print(f"Incident already ingested:", incident['incidentId'])
                self._update_parity(incident, existing_container)

            # redirected incidents have no data of value
            if "redirected" == incident['status'].lower():
                continue

            # create container to possibly save
            new_container = {
                "label": container_label,
                "name": incident["incidentName"],
                "severity": incident["severity"],
                "source_data_identifier": incident["source_data_identifier"],
                "status": self.statuses['container'].get(self.param.get("status", "default"), False),
                "tags": container_tags,
                'artifacts': self._compile_artifacts(incident)
            }

            # loop through each row in the filter rules
            for filter_rule in filter_list:
                # set default rule values
                rule_name = filter_rule.get("Rule Name", "")
                rule_action = filter_rule.get("Action", "").lower()
                rule_category = filter_rule.get("Rule Category", ["", ""])
                additional_comments = filter_rule.get("Additional Comments", "")

                # skip non-actionable rules if they slipped through the validation cracks
                if rule_action not in ["case", "close", "ingest", "ignore"]:
                    continue

                # get filter rule definitions
                incident_rule = filter_rule["Incident"].strip() if filter_rule.get("Incident", False) else "{}"
                incident_rule = json.loads(incident_rule)

                alert_rule = filter_rule["Alerts"].strip() if filter_rule.get("Alerts", False) else "{}"
                alert_rule = json.loads(alert_rule)

                entity_rule = filter_rule["Entities"].strip() if filter_rule.get("Entities", False) else "{}"
                entity_rule = json.loads(entity_rule)

                device_rule = filter_rule["Devices"].strip() if filter_rule.get("Devices", False) else "{}"
                device_rule = json.loads(device_rule)

                rule_count = len(incident_rule) + len(alert_rule) + len(entity_rule) + len(device_rule)
                if 0 == rule_count:
                    continue

                # initialize rule passing status, empty rules default to True
                pass_incident = False if 0 < len(incident_rule) else True
                pass_alert = False if 0 < len(alert_rule) else True
                pass_entity = False if 0 < len(entity_rule) else True
                pass_device = False if 0 < len(device_rule) else True

                # check to see if rules pass the match check
                if self._filter_rule_matches(incident_rule, incident):
                    pass_incident = True

                for alert in incident.get("alerts", []):
                    if self._filter_rule_matches(alert_rule, alert):
                        pass_alert = True

                    for entity in alert.get("entities", []):
                        if self._filter_rule_matches(entity_rule, entity):
                            pass_entity = True

                    for device in alert.get("devices", []):
                        if self._filter_rule_matches(device_rule, device):
                            pass_device = True

                # perform defined action if rule matches
                if pass_incident and pass_alert and pass_entity and pass_device:

                    # Ignore an incident, good for when different organizations handle the same incident feed
                    if "ignore" == rule_action:
                        action_taken = f"{rule_action}"

                    # Close incident in SOAR, update_parity() handles local containers if any were ingested
                    if "close" == rule_action:
                        # resolve incident in MDE
                        if "active" == incident['status'].lower():
                            self.debug_print(f"resolving incident in MDE")
                            # close incident in MDE
                            body = {
                                "status": "Resolved",
                                "assignedTo": self.param.get("assigned_to", False),
                                "classification": rule_category[0],
                                # DOESN'T LIKE:
                                # - InformationalExpectedActivity.ConfirmedUserActivity
                                # - FalsePositive.Clean
                                # - FalsePositive.InsufficientData
                                # - TruePositive.CompromisedUser
                                "determination": rule_category[1],
                                "comment": f"Incident closed from SOAR based on rule '{rule_name}': {additional_comments}"
                            }
                            data = json.dumps({key: val for key, val in body.items() if val and "" != f"{val}"})

                            url = f"{self.api_uri}{INCIDENT_SINGLE}".format(resource='security',
                                                                            incident_id=incident['incidentId'])

                            self._make_rest_call(url, data=data, method="patch")
                            self.debug_print("make_rest_call response:", self.response.json())

                        action_taken = f"{rule_action}"
                        self.debug_print(f"Close action taken for incident {incident['incidentId']}:",
                                         incident["incidentName"])

                    # Force-ingest an incident regardless of other rules
                    if "ingest" == rule_action and "active" == incident['status'].lower():
                        if not existing_container:
                            self.containers_to_save.append(new_container)
                            self.debug_print(f"Ingesting incident {incident['incidentId']} based on rule"
                                             f" - {rule_action}:", incident['incidentName'])
                        else:
                            self.debug_print(f"Rule action for {incident['incidentId']} is ingest, but it's already ingested:", existing_container["container_id"])
                        action_taken = f"{rule_action}"

                    # promote existing container to case or convert new container to case
                    if "case" == rule_action:
                        if existing_container and "case" != existing_container['container_type']:
                            phanrules.promote(existing_container)
                        else:
                            new_container['container_type'] = "case"
                            self.containers_to_save.append(new_container)

                        action_taken = f"{rule_action}"

            # no rule matches, continue with default behavior for the current incident
            if action_taken is True:
                continue

            if "ingest" == self.on_poll_behavior:
                self.containers_to_save.append(new_container)
            self.debug_print(f"Default action ({self.on_poll_behavior}) "
                             f" for incident {incident['incidentId']}:", incident["incidentName"])

        # Save all containers
        if self.containers_to_save:
            self.debug_print("Saving containers:", len(self.containers_to_save))
            response = self.save_containers(self.containers_to_save)
            self.debug_print("save_containers response:", response)
        else:
            self.debug_print("No containers to save:", self.containers_to_save)

        # Finalize ingestion
        message = f"Ingestion complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _get_filter_list(self, recurse: bool = True) -> list:
        filter_url = phanrules.build_phantom_rest_url("decided_list", self.filter_list)
        response = json.loads(phantom.requests.get(filter_url, verify=False).content)

        if not response.get("failed", False):
            return self._validate_filter_list(response["content"])

        success, message = phanrules.set_list(
            list_name=self.filter_list,
            values=[["Rule Name", "Action", "Incident", "Alerts", "Entities",
                     "Devices", "Additional Comments", "Category", "Status"]]
        )

        if recurse:
            return self._get_filter_list(recurse=False)

        # something is broken, but we don't talk about that...
        return [{}]

    def _validate_filter_list(self, filter_list: list) -> list:

        filter_rules = [{filter_list[0][index]: value for index, value in enumerate(row)} for row in filter_list[1:]]
        validated_rules = []

        valid_categories = self.categories.keys()
        valid_actions = ["case", "close", "ignore", "disable"]

        json_fields = ["Incident", "Alerts", "Entities", "Devices"]

        for r in range(0, len(filter_rules)):
            # Skip null rows
            null_check_list = [
                filter_rules[r].get("Rule Name", None),
                filter_rules[r].get("Action", None),
                filter_rules[r].get("Incident", None),
                filter_rules[r].get("Alerts", None),
                filter_rules[r].get("Entities", None),
                filter_rules[r].get("Devices", None),
                filter_rules[r].get("Additional Comments", None),
                filter_rules[r].get("Category", None),
            ]
            if any(x == None for x in null_check_list):
                self.debug_print("Skipping rule with wierd null values", filter_rules[r])
                continue

            # remove any silly wierd spacing issues due to human error
            regex = r"/(\s|\r?\n)+/m"
            filter_rules[r]["Rule Name"] = rp.sub(regex, " ", filter_rules[r]["Rule Name"]).strip()
            filter_rules[r]["Additional Comments"] = rp.sub(regex, " ", filter_rules[r]["Additional Comments"]).strip()
            errors = []

            # check action string
            action_string = (
                "" if not filter_rules[r].get("Action", "") else filter_rules[r].get("Action", "")).lower().strip()
            if action_string not in valid_actions:
                errors.append(f"Unknown action: '{action_string}'")

            # check json syntax
            valid_jsons = []
            for column in json_fields:
                try:
                    content = filter_rules[r].get(column, "")
                    content = content.strip() if content else ""  # sometimes empty values are null and just act wierd
                    if 0 == len(content):
                        continue

                    content = rp.sub(regex, " ", content)

                    while not isinstance(content, dict):
                        content = json.loads(content)

                    valid_jsons.append(content)
                    filter_rules[r][column] = json.dumps(content)

                except ValueError:
                    errors.append(f"Invalid JSON in '{column}'")

            # check for solely exclusion rule
            key_list = []
            for valid_json in valid_jsons:
                key_list = key_list + list(valid_json.keys())
            exclusion_count = len([v for v in key_list if v.startswith("!")])
            inclusion_count = len([v for v in key_list if not v.startswith("!")])
            if 0 < exclusion_count and 0 == inclusion_count:
                errors.append(f"Contains only '!exclusionary' criterion, add at least one inclusion")

            # check category
            category = (
                "" if not filter_rules[r].get("Category", "") else filter_rules[r].get("Category", "")).strip()
            if "close" == action_string and category not in valid_categories:
                errors.append(f"Invalid 'Category' supplied for closing action: {category}")

            # validate and log
            if 0 == len(errors):
                validated_rules.append(filter_rules[r])

            if 0 < len(errors):
                filter_rules[r]["Status"] = "; ".join(errors)
            elif "disabled" == action_string:
                filter_rules[r]["Status"] = "Disabled, Ok"
            else:
                filter_rules[r]["Status"] = "Active"

        # save updates
        validated_list = []
        validated_list.append(["Rule Name", "Action", "Incident", "Alerts", "Entities",
                               "Devices", "Additional Comments", "Category", "Status"])
        for r in filter_rules:
            validated_list.append([val for key, val in r.items()])
        phanrules.set_list(list_name=self.filter_list, values=validated_list)

        return validated_rules

    def _update_parity(self, incident: dict, container: dict) -> bool:
        """
        for parity between MDE and the SOAR, check for "resolved" and "redirected" statuses on returned incidents.
        For resolved incidents, check if a container exists in the SOAR for that incident and close it. For
        redirected incidents, check the targeted redirect incident to see if a corresponding container exists, then
        add the artifacts to that container instead of creating a new one, and close an existing container stating
        that it was redirected to the alternate container. Additionally, for incidents that already have a
        container, verify the title has not changed, as when more alerts are added to an existing incident, the name
        will often change.
        """

        incident_id = incident["incidentId"]
        container_id = container["id"]
        incident_status = incident.get("status", "").lower()
        container_status = container['status'].lower()
        incident_tags = incident.get("tags", [])
        container_tags = container["tags"]

        # Nobody cares
        if "resolved" == incident_status and "closed" == container_status:
            return True

        # closed in MDE, open in SOAR
        if "resolved" == incident_status and "closed" != container_status:
            phanrules.add_comment(container["id"], "Incident was resolved from MDE")
            phanrules.set_status(container["id"], "closed")
            return True

        # Open in MDE, closed in SOAR
        if "resolved" != incident_status and "closed" == container_status:
            # check for valid close tags in container
            valid_classification = False
            valid_determination = False
            valid_classifications = []
            valid_determinations = []
            for category in self.categories.items():
                classification, determination = category[1]
                valid_classifications.append(classification)
                valid_determinations.append(determination)
                if classification in container["tags"]:
                    valid_classification = classification
                if determination in container["tags"]:
                    valid_determination = determination

            # reopen a container if it wasn't closed properly
            if not valid_classification or not valid_determination:
                comment = f"Container is missing required MDE tags to close and is being reopened for proper closure. "
                if not valid_classification:
                    comment += f"Classification tag must be one of the following: {valid_classifications}"
                if not valid_determination:
                    comment += f"Determination tag must be one of the following: {valid_determinations}"
                phanrules.add_comment(container_id, comment)
                phanrules.set_status(container, "open")
                return False

            # close MDE incident with container close tags
            close_comment = f"Incident closed from SOAR: "
            data = {
                'status': "Resolved",
                'classification': classification,
                # DOESN'T LIKE:
                # - InformationalExpectedActivity.ConfirmedUserActivity
                # - FalsePositive.Clean
                # - FalsePositive.InsufficientData
                # - TruePositive.CompromisedUser
                'determination': determination,
                'tags': incident_tags + container_tags,
                'comment': close_comment
            }

            url = f"{self.api_uri}{INCIDENT_SINGLE}".format(resource='security', incident_id=incident_id)

            if not self._make_rest_call(url, data=data, method="patch"):
                return phantom.APP_ERROR

            return True

        # Add redirected comment to container in SOAR
        if "redirected" == incident_status:
            phanrules.add_comment(f"Incident redirected: {incident_id}")
            return True

        # Copy any additional artifacts from incident to container
        if "active" == incident_status:
            container["artifacts"] = self._compile_artifacts(incident, container_id)
            self.containers_to_save.append(container)
            return True

        self.debug_print("Unaccounted for status:", incident_status)

        return True

    def _dict_hash(self, dictionary: dict) -> dict:
        """
        Takes a dictionary input, sorts the keys so {'a': 1, 'b': 2} is the same as {'b': 2, 'a': 1} and returns the
        hash of the resulting json string.

        :param dictionary: input dictionary to be hashed
        :return: md5 hex hash of dictionary
        """
        dictionary = self._sort_dict(dictionary)
        dictionary_hash = hashlib.md5(str(dictionary).encode(), usedforsecurity=False)
        return dictionary_hash.hexdigest()

    def _sort_dict(self, dictionary: dict) -> dict:
        {k: dictionary[k] for k in sorted(dictionary)}
        for key, value in dictionary.items():
            if isinstance(value, dict):
                dictionary[key] = self._sort_dict(value)

        return dictionary

    def _compile_artifacts(self, incident: dict, container_id: int = None, odata_type: str = "incident") -> list:
        # prepare variables
        artifact_list = []
        this_artifact = {"cef": {}, "data": {}}
        odata_types = {
            "alerts": "alert",
            "devices": "device",
            "entities": "entity"
        }

        # set important defaults
        if "incident" == odata_type:
            this_artifact["name"] = incident.get("incidentName", "generic incident")
            this_artifact["description"] = incident.get("incidentUri", "generic incident")
            this_artifact["label"] = "incident"

        elif "alert" == odata_type:
            this_artifact["name"] = incident.get("title", "generic alert")
            this_artifact["description"] = incident.get("description", "generic alert")
            this_artifact["label"] = "alert"

        elif "device" == odata_type:
            this_artifact["name"] = incident.get("deviceDnsName", "unknown device")
            this_artifact["description"] = incident.get("rbacGroupName", "unknown device group")
            this_artifact["label"] = "device"

        elif "entity" == odata_type:

            if "File" == incident.get("entityType"):
                this_artifact["name"] = incident.get("fileName", "unknown file")
                this_artifact["description"] = incident.get("filePath", "unknown file location")
                this_artifact["label"] = "file"

            elif "Process" == incident.get("entityType"):
                this_artifact["name"] = incident.get("fileName", "unknown process")
                this_artifact["description"] = incident.get("filePath", "unknown process location")
                this_artifact["label"] = "process"

            elif "Registry" == incident.get("entityType"):
                this_artifact["name"] = incident.get("registryKey", "unknown registry key")
                this_artifact["description"] = incident.get("registryHive", "unknown registry hive")
                this_artifact["label"] = "registry"

            elif "User" == incident.get("entityType"):
                this_artifact["name"] = incident.get("userPrincipalName", "unknown user")
                this_artifact["description"] = incident.get("accountName", "unknown account")
                this_artifact["label"] = "user"

            else:
                this_artifact["name"] = incident.get("entityType", "unknown entity")

        else:
            this_artifact["name"] = "other"
            this_artifact["label"] = "artifact"

        # do a barrel roll!
        for artifact_name, artifact_value in incident.items():
            if artifact_name in odata_types.keys():
                for sub_artifact in artifact_value:
                    artifact_list = artifact_list + self._compile_artifacts(sub_artifact, container_id,
                                                                            odata_types.get(artifact_name, "other"))

            else:
                if artifact_name in self.cef:
                    this_artifact['cef'][artifact_name] = artifact_value
                this_artifact['data'][artifact_name] = artifact_value

        # finish up the artifact and save
        this_artifact['source_data_identifier'] = self._dict_hash(this_artifact)

        if container_id:
            this_artifact['id'] = container_id

        artifact_list.append(this_artifact)

        return artifact_list

    def _filter_rule_matches(self, rule_definition: dict, target_dictionary: dict) -> bool:
        for rule_key, rule_value in rule_definition.items():
            rule_type = "inclusion" if not rule_key.startswith("!") else "exclusion"
            target_value = target_dictionary.get(rule_key.strip("!"), "").lower()

            # check for inclusion rule match
            if "inclusion" == rule_type and rule_value.lower() not in target_value:
                return False
            if "exclusion" == rule_type and rule_value.lower() in target_value:
                return False

        return True

    def _handle_widget_update(self) -> bool:
        url = f"{self.api_uri}{INCIDENT_SINGLE}".format(resource='security',
                                                        incident_id=self.param['incident_id'])

        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        self.r_json["source_data_identifier"] = self._sdi(self.r_json)

        uri_prefix = rp.split("incident", self.r_json["incidentUri"])[0]
        alert_links = {"alert_link": f"{uri_prefix}alerts/{alert['alertId']}" for alert in self.r_json["alerts"]}

        self.action_result.add_data(alert_links)

        message = f"Updated widget for {self.param['incident_id']}"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def handle_action(self, param) -> bool:
        self.param = param
        self.save_progress(f"Starting action: {self.action_id}\n{json.dumps(self.param, indent=4)}")

        if not getattr(self, f"_handle_{self.action_id}")() and self.r_json:
            self.set_status_save_progress(phantom.APP_ERROR, f"{self.action_id} has no _handler function")

        return self.get_status()

    def _sdi(self, input_dictionary: dict) -> str:
        # incidentId
        if input_dictionary.get("incidentId", False):
            self._rd.seed(input_dictionary["incidentId"])

        # alertId
        if input_dictionary.get("alertId", False):
            self._rd.seed(input_dictionary["alertId"])

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
        self.save_progress(f"Action execution time: {datetime.now() - self._action_start_time} seconds")
        return phantom.APP_SUCCESS

    # ------------------------ #
    #   SOAR REST API CALLS    #
    # ------------------------ #

    def _get_asset_name(self):
        # Make REST call to SOAR
        uri = phanrules.build_phantom_rest_url("asset", self.get_asset_id())
        return json.loads(phanrules.requests.get(uri, verify=False).text).get("name", "unnamed_asset")

    def _get_asset_tags(self):
        # Make REST call to SOAR
        uri = phanrules.build_phantom_rest_url("asset", self.get_asset_id())
        return json.loads(phanrules.requests.get(uri, verify=False).text).get("tags", [])

    def _get_asset_label(self):
        # Make REST call to SOAR
        uri = phanrules.build_phantom_rest_url("asset", self.get_asset_id())
        return json.loads(phanrules.requests.get(uri, verify=False).text).get("configuration", {}).get("ingest",
                                                                                                       {}).get(
            "container_label", None)


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
