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
import urllib

import requests

# If you find errors or would like to help contribute, please see:
# https://github.com/supergnaw/phMDE-Security-Center

import phantom.rules as phanrules
import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
import encryption_helper

import json
import time
from datetime import datetime, timedelta
from requests import Response
import hashlib, uuid, random
import replus as rp

from mdesecuritycenter_consts import *

# Custom helper classes
from authentication_token import AuthenticationToken
from settings_parser import SettingsParser


def parse_exception_message(e: Exception) -> str:
    try:
        if 1 < len(e.args):
            return f"Exception [{e.args[0]}]: {e.args[1]}"
        return f"Exception: {e.args[0]}"
    except Exception:
        return "Failed to parse exception error message"


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class MDESecurityCenter_Connector(BaseConnector):
    """
    Normalization Properties

    Phantom has a somewhat obtuse way of accessing app information such as versions, names, etc., through the use of API
    calls. Because of this, these properties are meant to provide a more direct way to access this data. These values
    are stored within the class and initialized as None until they are called. After the first use, the value is updated
    via an API call, which is then used for each successive usage, reducing internal API calls and releasing resources
    for other computational requirements.

    :property self.app_json:
    :property self.app_id:
    :property self.app_version:
    :property self.asset_name:
    :property self.label:
    :property self.tags:
    :property self.cef:
    :property self.action_id:
    :property self.action_result:
    """

    @property
    def app_id(self) -> str:
        if not self._app_id:
            self._app_id = str(self.get_app_json().get("appid", 'unknown app id'))
        return self._app_id

    _app_id: str = None

    @property
    def app_version(self) -> str:
        if not self._app_version:
            self._app_version = str(self.get_app_json().get("app_version", '0.0.0'))
        return self._app_version

    _app_version: str = None

    @property
    def asset_id(self) -> str:
        if not self._asset_id:
            self._asset_id = str(self.get_asset_id())
        return self._asset_id

    _asset_id: str = None

    @property
    def asset_name(self) -> str:
        if not self._asset_name:
            self._asset_name = phantom.requests.get(
                phanrules.build_phantom_rest_url("asset", self.asset_id),
                verify=self.config.verify_server_cert
            ).json.get("name", 'unnamed_asset')
        return self._asset_name

    _asset_name: str = None

    @property
    def label(self) -> str:
        if not self._label:
            self._label = phantom.requests.get(
                phanrules.build_phantom_rest_url("asset", self.asset_id),
                verify=self.config.verify_server_cert
            ).json.get("configuration", {}).get("ingest", {}).get("container_label", 'events')
        return self._label

    _label: str = None

    @property
    def tags(self) -> list:
        if not self._tags:
            self._tags = phantom.requests.get(
                phanrules.build_phantom_rest_url("asset", self.asset_id),
                verify=self.config.verify_server_cert
            ).json.get("tags", [])
        return self._tags

    _tags: list = None

    @property
    def cef(self) -> list:
        if not self._cef:
            uri = phanrules.build_phantom_rest_url("cef") + "?page_size=0"
            response = phantom.requests.get(uri, verify=False)

            if 200 > response.status_code or 299 < response.status_code:
                return []

            self._cef = [cef['name'] for cef in json.loads(response.text)['data']]
        return self._cef

    _cef: list = None

    @property
    def action_id(self) -> str:
        if not self._action_id:
            self._action_id = str(self.get_action_identifier())
        return self._action_id

    _action_id: str = None

    @property
    def config_defaults(self) -> dict:
        if not self._config_defaults:
            defaults = {}
            for default_name, meta_data in self.get_app_json().get("configuration", {}).items():
                if "ph" == meta_data["data_type"]:
                    continue

                if "numeric" == meta_data["data_type"]:
                    defaults[default_name] = int(meta_data.get("default", 0))
                elif "boolean" == meta_data["data_type"]:
                    defaults[default_name] = bool(meta_data.get("default", False))
                else:
                    defaults[default_name] = str(meta_data.get("default", "None"))
            self._config_defaults = defaults
        return self._config_defaults

    _config_defaults: dict = None

    @property
    def action_result(self) -> ActionResult:
        if not self._action_result:
            self._action_result = self.add_action_result(ActionResult({'action started': self.action_id}))
        return self._action_result

    _action_result: ActionResult = None

    action_data: dict = {}

    def __init__(self):

        # Call the BaseConnector's init first
        super(MDESecurityCenter_Connector, self).__init__()

        self._action_start_time = datetime.now()

        self.state: dict = None
        self.response = None
        self.live_response: dict = {}
        self.tokens: dict = {
            "security": AuthenticationToken(token=""),
            "securitycenter": AuthenticationToken(token="")
        }
        self.config: SettingsParser = None

        self.resources: list = ['security', 'securitycenter']
        self.containers_to_save: list = []

        # Input validation helper variables
        self.statuses: dict = {
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

        self.categories: dict = {
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

    @property
    def field_map(self) -> dict:
        return json.loads(self.get_config().get("field_mapping", "{}"))

    @property
    def api_uri(self) -> str or bool:
        return self.get_config().get("api_uri", "").replace("*", "{resource}")

    @property
    def login_uri(self) -> str:
        return "https://login.microsoftonline.com" if "api-gov" not in self.api_uri else "https://login.microsoftonline.us"

    # ========== #
    # REST CALLS #
    # ========== #

    # ------------------- #
    # Primary REST Caller #
    # ------------------- #

    def _make_rest_call(self, endpoint: str, method: str = "get", verify: bool = True, **kwargs) -> RetVal:
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

        # Hey now, you can't do that type of REST call!
        try:
            request_func = getattr(phantom.requests, method.lower())
        except AttributeError:
            message = f"Invalid requests method: {method}"
            self.error_print(message)
            return RetVal(self.action_result.set_status(phantom.APP_ERROR, message), message)

        # Ensure authentication token is current
        resource = rp.search(pattern=r"/[^\w]+([^\.]+)\.microsoft/i", string=endpoint).group(1)
        if not self._authenticate(resource=resource):
            message = f"Couldn't authenticate to retrieve {resource} token"
            return RetVal(self.set_status_save_progress(phantom.APP_ERROR, message), message)

        # Default headers and add authorization token as necessary
        if "headers" not in kwargs:
            kwargs["headers"] = {"Content-Type": "application/json"}
        if "Accept" not in kwargs["headers"].keys():
            kwargs["headers"]["Accept"] = "application/json"
        if resource in self.resources:
            kwargs["headers"]["Authorization"] = f"Bearer {self.tokens[resource].token}"
        if "data" in kwargs and isinstance(kwargs["data"], dict):
            kwargs["data"] = json.dumps(kwargs["data"])

        # Make the REST call
        try:
            response = request_func(endpoint, verify=verify, **kwargs)
            self.save_progress(f"Made {method.upper()} request to: {endpoint}")
        except Exception as e:
            message = f"Exception occurred while connecting to server: {parse_exception_message(e)}"
            return RetVal(self.set_status_save_progress(phantom.APP_ERROR, message), message)

        # Response said to retry
        if 429 == response.status_code and 300 < int(response.headers.get('Retry-After', 301)):
            message = f"Error occurred [{response.status_code}]: {str(response.text)}"
            return RetVal(self.set_status_save_progress(phantom.APP_ERROR, status_message=message))

        if 429 == response.status_code and 300 >= int(response.headers.get('Retry-After', 301)):
            self.save_progress(f"Retrying after {response.headers.get('Retry-After', 301)} seconds")
            time.sleep(int(response.headers['Retry-After']) + 1)
            return self._make_rest_call(endpoint, verify=verify, **kwargs)

        return self._process_response(response=response)

    # ------------------- #
    # Response Processors #
    # ------------------- #

    def _process_response(self, response: Response = None) -> RetVal:
        """
        Processes a requests response object according to the content type.

        :param response: requests response object
        :return: [status, JSON|message]
        """

        if 'json' in response.headers.get('Content-Type', '').lower():
            return self._process_json_response(response=response)

        if 'html' in response.headers.get('Content-Type', '').lower():
            return self._process_html_response(response=response)

        if not response.text:
            return self._process_empty_response(response=response)

        # If we get here, it's because there's an error
        if hasattr(self.action_result, 'add_debug_data'):
            self.action_result.add_debug_data({'r_status_code': response.status_code})
            self.action_result.add_debug_data({'r_text': response.text})
            self.action_result.add_debug_data({'r_headers': response.headers})

        message = f"Can't process response from server [{response.status_code}]: {response.text}"
        return RetVal(self.set_status_save_progress(phantom.APP_ERROR, message), message)

    def _process_json_response(self, response: Response = None) -> RetVal:
        """
        Attempts to parse a JSON content response.

        :param response: request response object
        :return: [status, JSON|message]
        """

        # Parse! That!! JSON!!! (with enthusiasm!!!!)
        try:
            resp_json = response.json()
            if 200 <= response.status_code <= 399:
                return RetVal(self.action_result.set_status(phantom.APP_SUCCESS), resp_json)
            return self._process_json_error_response(response)
        except Exception as e:
            message = f"Unable to parse JSON response: {parse_exception_message(e)}"
            return RetVal(self.set_status_save_progress(phantom.APP_ERROR, message), message)

        # There's a generic error in our midst
        message = (
            f"!!! {str(self.r_json.get('error', {}).get('code', 'Unknown'))} error occurred [{response.status_code}]:"
            f"{str(self.r_json.get('error', {}).get('message', 'No message available'))}"
        )
        return RetVal(self.set_status_save_progress(phantom.APP_ERROR, message), message)

    def _process_json_error_response(self, response: Response) -> RetVal:
        resp_json = response.json()
        error_code = resp_json.get("error", {}).get("code", "Unknown code")
        error_message = resp_json.get("error", {}).get("message", "Unknown message")
        message = f"Response Error [{response.status_code}]: {error_code} - {error_message}"
        return RetVal(self.set_status_save_progress(phantom.APP_ERROR, message), message)

    def _process_html_response(self, response: Response = None) -> RetVal:
        """
        Treats an HTML response like an error.

        :param response: request response object
        :return: [status, message]
        """

        try:
            # Remove extra elements
            content = rp.sub(
                repl="", string=response.text, pattern=(
                    "/(<script.*?(?=<\/script>)<\/script>|<style.*?(?=<\/style>)<\/style>|"
                    "<footer.*?(?=<\/footer>)<\/footer>|<nav.*?(?=<\/nav>)<\/nav>)/sim"
                )
            )
            # Clear out extra whitespace and empty lines
            error_text = rp.sub(pattern="/\s+/sim", repl=" ", string=content).strip()
        except Exception as e:
            error_text = f"Cannot parse error details: {parse_exception_message(e)}"

        if not error_text:
            error_text = "Error message unavailable. Please check the asset configuration and/or the action parameters"

        # Use f-strings, we are not uncivilized heathens.
        message = f"Status Code: {self.response.status_code}. Raw data from server:\n{error_text}\n"
        return RetVal(self.set_status_save_progress(phantom.APP_ERROR, status_message=message))

    def _process_empty_response(self, response: Response = None) -> RetVal:
        """
        This function is used to process empty response.
        :param response: response data
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if self.response.status_code in [200, 204]:
            return RetVal(self.set_status_save_progress(phantom.APP_SUCCESS))

        message = f"Status Code: {response.status_code}. Error: Empty response and no information in the header"
        return RetVal(self.set_status_save_progress(phantom.APP_ERROR, status_message=message))

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

    # ============== #
    # AUTHENTICATION #
    # ============== #

    def _authenticate(self, resource: str, force_refresh: bool = False) -> bool:
        """
        Checks for an authentication token for a given resource, and if none exist, generates a new one

        :param resource: the resource to authenticate with, 'security' or 'securitycenter'
        :param force_refresh: force a refresh of the authentication tokens if saved in cache
        :return: bool
        """
        self.save_progress(f"In action handler for authenticate")
        self.debug_print("parameters:", {"resource": resource, "force_refresh": force_refresh})

        # Instantiate new AuthenticationToken object as needed
        if not self.tokens.get(resource, False) or force_refresh:
            self.tokens[resource] = AuthenticationToken(token="")

        # AuthenticationToken allocated has not yet expired
        if self.tokens[resource].token:
            summary = self.tokens[resource].summary()
            message = f"Authentication for {resource} valid until {summary['expires_on']} ({summary['expires_in']})"
            return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

        method, endpoint = (f"GET {self.config.login_uri}/"
                            f"{self.config.tenant_id}/"
                            f"oauth2/token").split(" ", 1)

        # Prepare to request a new token
        uri = f"{self.config.login_uri}/{self.config.tenant_id}/oauth2/token"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = urllib.parse.urlencode({
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
            'resource': self.api_uri.format(resource=resource),
            'grant_type': 'client_credentials'
        }).encode("utf-8")

        # The authentication request is a bit different from other REST calls so let's make a special one!
        try:
            resp_json = phantom.requests.get(uri=uri, headers=headers, data=data).json()
            if not resp_json:
                return resp_json
            self.debug_print("response json:", resp_json)
        except Exception as e:
            message = parse_exception_message(e)
            return self.set_status_save_progress(phantom.APP_ERROR, status_message=message)

        self.tokens[resource].update(token=str(resp_json.get('access_token', '')))

        summary = self.tokens[resource].summary()
        message = f"Authentication successful for {resource}: expires on {summary['expires_on']} ({summary['expires_in']})"
        self.save_progress(message)
        return self.action_result.set_status(phantom.APP_SUCCESS, status_message=message)

    # ---------------------- #
    # Authentication Helpers #
    # ---------------------- #

    # ======================== #
    # ACTION HANDLER FUNCTIONS #
    # ======================== #

    # ---------------------- #
    # Primary Action Handler #
    # ---------------------- #

    def handle_action(self, param: dict = None) -> bool:
        # Empty default param definition
        if param is None:
            param = {}

        self.debug_print(f"Using params: {param}")

        if hasattr(self, f"_handle_{self.action_id}"):
            return self.set_status_save_progress(
                status_code=getattr(self, f"_handle_{self.action_id}")(**param),
                status_message="Action completed")

        # Missing handler function for action
        message = f"{self.action_id} has no handler function: '_handle_{self.action_id}'"
        return self.set_status_save_progress(phantom.APP_ERROR, status_message=message)

    # ------------------ #
    # Connectivity Tests #
    # ------------------ #

    def _handle_clear_authentication_tokens(self) -> bool:
        """
        Clears cached authentication tokens

        :return: status
        """
        self.save_progress(f"In action handler for clear_authentication_tokens")
        self.debug_print("parameters:", None)

        for resource in self.resources:
            self.tokens[resource] = AuthenticationToken(token="")

        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message="Authentication tokens cleared.")

    def _handle_verify_authentication_tokens(self, force_refresh: bool = False):
        """
        Verifies authentication tokens, or forces a token refresh

        :param force_refresh: force refresh saved tokens
        :return: status
        """
        self.save_progress(f"In action handler for verify_authentication_tokens")
        self.debug_print("parameters:", {"force_refresh": force_refresh})

        for resource in self.resources:
            if not self._authenticate(resource=resource, force_refresh=force_refresh):
                message = f"Could not authenticate with {resource}"
                self.error_print(message)
                self.action_result.set_status(phantom.APP_ERROR, message)
            else:
                self.debug_print(f"Token [{resource}]:", self.tokens[resource].summary())
                self.action_result.add_data({resource: self.tokens[resource].parsed})

        message = "Successfully verified authentication tokens."
        if not self.action_result.get_status():
            message = "Failed to verify authentication tokens."
        return self.set_status_save_progress(self.action_result.get_status(), message)

    def _handle_test_connectivity(self, force_refresh: bool = False) -> bool:
        """
        Tests connection by attempting to authenticate to API

        :param force_refresh:
        :return: status
        """
        self.save_progress(f"In action handler for test_connectivity")
        self.debug_print("parameters:", {"force_refresh": force_refresh})

        if force_refresh:
            self.tokens = {}

        for resource in self.resources:
            self._authenticate(resource=resource)

        self._handle_list_incidents(top=1)

        [self.action_result.add_data(token.summary()) for t, token in self.tokens.items()]
        self.debug_print("self.action_result.get_data():", self.action_result.get_data())

        tokens = {resource: token.summary() for resource, token in self.tokens.items() if 0 < token.expires_on}
        self.save_progress(f"Active access tokens:\n{json.dumps(tokens, indent=4)}")
        return self.action_result.set_status(phantom.APP_SUCCESS, status_message="Test complete")

    # --------- #
    # Incidents #
    # --------- #

    def _handle_list_incidents(self, odata_filter: str = "", top: int = 100, skip: int = 0) -> bool:
        """
        The list incidents API allows you to sort through incidents to create an informed cybersecurity response. It
        exposes a collection of incidents that were flagged in your network, within the time range you specified in your
        environment retention policy. The most recent incidents are displayed at the top of the list. Each incident
        contains an array of related alerts, and their related entities.

        :param odata_filter: on the `lastUpdateTime`, `createdTime`, `status`, and `assignedTo` properties
        :param top: get only the top x results
        :param skip: skip the first x results
        :return: status
        """
        self.save_progress(f"In action handler for list_incidents")
        self.debug_print("parameters:", {"odata_filter": odata_filter, "top": top, "skip": skip})

        params = {
            "$top": max(0, top),
            "$skip": max(0, skip)
        }
        if isinstance(odata_filter, str) and 0 < len(odata_filter.strip()):
            params["$filter"] = odata_filter

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

        method, endpoint = (f"GET {self.api_uri.format(resource='security')}/"
                            f"api/incidents").split(" ", 1)

        returned_incidents = []

        for param in param_set:
            self.debug_print("params:", param)
            status, resp_json = self._make_rest_call(endpoint, params=param, method=method)
            if not status:
                self.error_print("Error:", "REST call to list incidents failed")
                return status

            self.debug_print("Returned:", f"{len(resp_json['value'])} incidents...")

            for incident in resp_json['value']:
                incident["source_data_identifier"] = self._sdi(incident)
                for i, alert in enumerate(incident["alerts"]):
                    incident["alerts"][i]["source_data_identifier"] = self._sdi(alert)
                self.action_result.add_data(incident)
                returned_incidents.append(incident)

        self.action_data["list_incidents"] = returned_incidents
        message = f"Returned {returned_incidents} incidents"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_incident(self, incident_id: int) -> bool:
        """
        Retrieves a specific incident by its ID

        :param incident_id:
        :return: status
        """
        self.save_progress(f"In action handler for get_incident")
        self.debug_print("parameters:", {"incident_id": incident_id})

        method, endpoint = (f"GET {self.api_uri.format(resource='security')}/"
                            f"api/incidents/{incident_id}").split(" ", 1)

        status, resp_json = self._make_rest_call(endpoint, method="get")

        if not status:
            return status

        resp_json["source_data_identifier"] = self._sdi(resp_json)
        incident = {key: val for key, val in resp_json.items() if not key.startswith("@")}

        self.action_result.add_data(incident)
        self.action_data["get_incident"] = incident

        message = f"Retrieved incident {incident_id}"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_update_incident(self, incident_id: int, comment: str, status: str = "default",
                                assigned_to: str = None, category: str = None, tags: str = "",
                                remove_tags: bool = False) -> bool:
        self.save_progress(f"In action handler for update_incident")
        self.debug_print("parameters:", {
            "incident_id": incident_id,
            "comment": comment,
            "status": status,
            "assigned_to": assigned_to,
            "category": category,
            "tags": tags,
            "remove_tags": remove_tags
        })

        # 275376
        # get current container tags
        if not remove_tags:
            if not self._handle_get_incident(incident_id=incident_id):
                return phantom.APP_ERROR

            incident_tags = self.action_result.get_data()[-1].get("tags", [])

            if incident_tags:
                tags = str(tags + f",{','.join(incident_tags)}").strip(",")
                self.save_progress(f"Joined new tags with existing tags: '{tags}'")

        data = {"comment": comment}
        if "default" != status and status in self.statuses["incident"].keys():
            data["status"] = self.statuses['incident'].get(status)
        if assigned_to:
            data["assignedTo"] = assigned_to
        if self.categories.get(category, False):
            # DOESN'T LIKE:
            # - InformationalExpectedActivity.ConfirmedUserActivity
            # - FalsePositive.Clean
            # - FalsePositive.InsufficientData
            # - TruePositive.CompromisedUser
            data["classification"] = self.categories[category][0]
            data["determination"] = self.categories[category][1]
        if tags:
            data["tags"] = [tag.strip() for tag in tags.split(",") if tag.strip()]

        method, endpoint = (f"PATCH {self.api_uri.format(resource='security')}/"
                            f"api/incidents/{incident_id}").split(" ", 1)

        self.debug_print("data:", data)

        status, resp_json = self._make_rest_call(endpoint, method=method, data=data)

        if not status:
            return status

        resp_json["source_data_identifier"] = self._sdi(resp_json)
        response = {key: val for key, val in resp_json.items() if not key.startswith("@")}

        self.action_result.add_data(response)
        self.action_data["update_incident"] = response

        message = f"Updated incident: {incident_id}:\n{resp_json}"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    # ------ #
    # Alerts #
    # ------ #

    def _handle_list_alerts(self, odata_filter: str = None, top: int = 500, skip: int = 0) -> bool:
        self.save_progress(f"In action handler for list_alerts")
        self.debug_print("parameters:", {
            "odata_filter": odata_filter, "top": top, "skip": skip
        })

        params = {"$filter": odata_filter, "$top": top, "$skip": skip, "$expand": "evidence"}

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

        alert_list = []

        for param in param_set:
            status, response = self._make_rest_call(url, params=param, method="get")

            if not status:
                continue

            for alert in response["value"]:
                alert["source_data_identifier"] = self._sdi(alert)
                alert_list.append(alert)

        message = f"Returned {len(alert_list)} alerts"
        self.action_result.add_data(alert_list)
        self.action_data["list_alerts"] = alert_list
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

    # --------------- #
    # Library Actions #
    # --------------- #

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

        message = f"get_action complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_action_result(self) -> object:
        url = f"{self.api_uri}{LIVE_RESPONSE_ACTION_RESULT}".format(resource="securitycenter",
                                                                    action_id=self.param['action_id'],
                                                                    command_index=self.param['command_index'])

        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"get_action_result complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    # -------------- #
    # Investigations #
    # -------------- #

    def _handle_list_investigations(self) -> object:
        params = {f"${k}": v for k, v in self.param.items() if v and k in ['filter', 'top', 'skip']}
        url = f"{self.api_uri}{INVESTIGATION_LIST}".format(resource="securitycenter")

        if not self._make_rest_call(url, params=params, method="get"):
            return phantom.APP_ERROR

        [self.action_result.add_data(action) for action in self.r_json['value']]

        message = f"list_investigations complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_investigation(self) -> object:
        url = f"{self.api_uri}{INVESTIGATION_SINGLE}".format(resource='securitycenter',
                                                             investigation_id=self.param['investigation_id'])

        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"get_investigation complete"
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

        message = f"start_investigation complete"
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

        message = f"collect_investigation_package complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    # --------------- #
    # Machine Actions #
    # --------------- #

    def _handle_list_machine_actions(self) -> object:
        params = {f"${k}": v for k, v in self.param.items() if v and k in ['filter', 'top', 'skip']}
        url = f"{self.api_uri}{MACHINE_LIST_ACTIONS}".format(resource='securitycenter',
                                                             machine_id=self.param['machine_id'])

        if not self._make_rest_call(url, params=params, method="get"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"list_machine_actions complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_isolate_machine(self) -> object:
        url = f"{self.api_uri}{MACHINE_ISOLATE}".format(resource='securitycenter',
                                                        machine_id=self.param['machine_id'])

        if not self._make_rest_call(url, method="post"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"isolate_machine complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_unisolate_machine(self) -> object:
        url = f"{self.api_uri}{MACHINE_UNISOLATE}".format(resource='securitycenter',
                                                          machine_id=self.param['machine_id'])

        if not self._make_rest_call(url, method="post"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"unisolate_machine complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    # ----- #
    # Files #
    # ----- #

    def _handle_get_file_info(self) -> object:
        url = f"{self.api_uri}{FILE_INFO}".format(file_id=self.param['file_hash'])

        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"get_file_info complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_get_file_stats(self) -> object:
        url = f"{self.api_uri}{FILE_STATS}".format(file_id=self.param['file_id'])

        if not self._make_rest_call(url, method="get"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"get_file_stats complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _handle_quarantine_file(self) -> object:
        url = f"{self.api_uri}{FILE_QUARANTINE}".format(machine_id=self.param['machine_id'])

        if not self._make_rest_call(url, method="post"):
            return phantom.APP_ERROR

        self.action_result.add_data({key: val for key, val in self.r_json.items() if not key.startswith("@")})

        message = f"quarantine_file complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    # ------- #
    # ON POLL #
    # ------- #

    def _handle_test_ingest_rules(self, incident_id: int) -> bool:
        if not self._handle_get_incident(incident_id=incident_id):
            return self.set_status_save_progress(status=phantom.APP_ERROR, status_message="failed to get incident")

        incident = self.action_result.get_data()[-1]
        self.debug_print("incident:", incident)
        rule = self._detect_filter_rule(incident)

        if not rule:
            self.debug_print("no rules detected, using default")
            rule = self.config.on_poll_behavior

        self.debug_print("rule:", rule)

        return True

    def _detect_filter_rule(self, incident: dict):
        detected_rule = None

        for filter_rule in self._get_filter_list():
            # skip non-actionable rules if they slipped through the validation cracks
            if filter_rule.get("Action", "").lower() not in ["case", "close", "ingest", "ignore"]:
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
                if "ignore" == filter_rule.get("Action", "").lower():
                    detected_rule = filter_rule

                # Close incident in SOAR, update_parity() handles local containers if any were ingested
                if "close" == filter_rule.get("Action", "").lower():
                    detected_rule = filter_rule

                # Force-ingest an incident regardless of other rules
                if "ingest" == filter_rule.get("Action", "").lower() and "active" == incident['status'].lower():
                    detected_rule = filter_rule

                # promote existing container to case or convert new container to case
                if "case" == filter_rule.get("Action", "").lower():
                    detected_rule = filter_rule

        return detected_rule

    def _handle_on_poll(self) -> bool:
        self.save_progress(f"In action handler for on_poll")
        self.debug_print("on_poll config:", {
            "max_incidents": self.config.max_incidents,
            "mde_ingest_comment": self.config.mde_ingest_comment,
            "mde_closure_comment": self.config.mde_closure_comment,
            "filter_list": self.config.filter_list,
            "field_mapping": self.config.field_mapping,
            "on_poll_behavior": self.config.on_poll_behavior
        })

        x_hours_ago = (datetime.utcnow() - timedelta(hours=self.config.ingest_window)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        params = {
            "odata_filter": f"createdTime gt {x_hours_ago}",
            "top": int(self.config.max_incidents)
        }
        self.debug_print("Getting incidents")
        self.debug_print("params:", params)

        result = self._handle_list_incidents(**params)
        if not result:
            return self.set_status_save_progress(phantom.APP_ERROR, "Failed to fetch incidents.")
        else:
            incidents = self.action_data["list_incidents"]
            if 0 == len(incidents):
                return self.set_status_save_progress(phantom.APP_SUCCESS, "No incidents returned")
            elif 1 == len(incidents):
                self.debug_print(f"Successfully fetched {len(incidents)} incident")
            else:
                self.debug_print(f"Successfully fetched {len(incidents)} incidents")

        # search for any existing containers
        source_data_identifiers = []
        for incident in incidents:
            if incident['source_data_identifier']:
                source_data_identifiers.append(incident['source_data_identifier'])

        existing_containers = {}
        if source_data_identifiers:
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

        containers_to_save = []

        # perform rule actions on incidents
        for incident in incidents:
            # update parity
            existing_container = existing_containers.get(incident["source_Data_identifier"], None)
            if existing_container:
                self.debug_print(f"Incident already ingested:", incident['incidentId'])
                self._update_parity(incident, existing_container)
                continue

            # redirected incidents have no data of value
            if "redirected" == incident['status'].lower():
                continue

            detected_rule = self._detect_filter_rule(incident)
            action_comment = self._create_aciton_comment(detected_rule)
            if action_comment:
                self.debug_print(action_comment, incident['incidentId'])

            if "ignore" == detected_rule.get("Action", "").lower():
                continue

            if "close" == detected_rule.get("Action", "").lower():
                if not self._handle_update_incident(incident_id=incident["incidentId"],
                                                    comment=action_comment,
                                                    category=detected_rule.get("Category", "")):
                    self.error_print(f"Failed to close incident:", incident['incidentId'])
                else:
                    self.debug_print(f"Closed incident:", incident['incidentId'])
                continue

            if "ingest" == detected_rule.get("Action", "").lower():
                containers_to_save.append({
                    "label": self.label,
                    "name": incident["incidentName"],
                    "severity": incident["severity"],
                    "source_data_identifier": incident["source_data_identifier"],
                    "status": "New",
                    "tags": self.tags,
                    "artifacts": self._compile_artifacts(incident)
                })
                continue

            if "case" == detected_rule.get("Action", "").lower():
                containers_to_save.append({
                    "label": self.label,
                    "name": incident["incidentName"],
                    "severity": incident["severity"],
                    "source_data_identifier": incident["source_data_identifier"],
                    "container_type": "case",
                    "status": "New",
                    "tags": self.tags,
                    "artifacts": self._compile_artifacts(incident)
                })
                continue

            if "ingest" == self.config.on_poll_behavior:
                self.debug_print("No rules matches so using default behavior 'ingest':", incident["incidentId"])
                self.containers_to_save.append({
                    "label": self.label,
                    "name": incident["incidentName"],
                    "severity": incident["severity"],
                    "source_data_identifier": incident["source_data_identifier"],
                    "status": "New",
                    "tags": self.tags,
                    "artifacts": self._compile_artifacts(incident)
                })

        # Save containers
        if containers_to_save:
            self.debug_print("Saving containers:", len(containers_to_save))
            response = self.save_containers(self.containers_to_save)
            self.debug_print("save_containers response:", response)
        else:
            self.debug_print("No containers to save:", self.containers_to_save)

        # Finalize ingestion
        message = f"Ingestion complete"
        return self.set_status_save_progress(phantom.APP_SUCCESS, status_message=message)

    def _create_aciton_comment(self, rule) -> str:
        action = rule.get("Action", None)
        rule_name = rule.get("Rule Name", "")
        comments = rule.get("Additional Comments", "")

        actions = {
            "ignore": "Ignoring",
            "close": "Closing",
            "ingest": "Ingesting",
            "case": "Creating case for"
        }

        if rule.get("Action", None) not in actions.keys():
            return ""

        return (f"{actions.get(rule['Action'])} incident based on '"
                f"{rule.get('Rule Name', 'no rule')}': "
                f"{rule.get('Additional Comments')}").strip().strip(":")

    def _handle_on_poll_old(self) -> bool:
        # generate timestamp for ingestion
        x_hours_ago = (datetime.utcnow() - timedelta(hours=self.config.ingest_window)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        container_label = self.label
        container_tags = self.tags

        # fetch the incidents
        url = f"{self.api_uri}{INCIDENT_LIST}".format(resource='security')
        incident_count = 0
        incidents = []
        target = self.mconfig.ax_incidents
        params = {
            "$filter": f"createdTime gt {x_hours_ago}",
            "$top": min(self.config.max_incidents, LIST_INCIDENTS_LIMIT),
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
                            self.debug_print(
                                f"Rule action for {incident['incidentId']} is ingest, but it's already ingested:",
                                existing_container["container_id"])
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

            if "ingest" == self.config.on_poll_behavior:
                self.containers_to_save.append(new_container)
            self.debug_print(f"Default action ({self.config.on_poll_behavior}) "
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
        filter_url = phanrules.build_phantom_rest_url("decided_list", self.config.filter_list)
        response = json.loads(phantom.requests.get(filter_url, verify=False).content)

        if not response.get("failed", False):
            return self._validate_filter_list(response["content"])

        success, message = phanrules.set_list(
            list_name=self.config.filter_list,
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
                filter_rules[r].get("Label", None),
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

            if not filter_rules[r]["Label"]:
                filter_rules[r]["Label"] = self.label

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
        validated_list.append(["Rule Name", "Action", "Label", "Incident", "Alerts", "Entities",
                               "Devices", "Additional Comments", "Category", "Status"])
        for r in filter_rules:
            validated_list.append([val for key, val in r.items()])
        phanrules.set_list(list_name=self.config.filter_list, values=validated_list)

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
            close_category = False
            valid_classification = False
            valid_determination = False
            valid_classifications = []
            valid_determinations = []
            for category in self.categories.items():
                classification, determination = category[1]
                valid_classifications.append(classification)
                valid_determinations.append(determination)
                if classification in container["tags"] and determination in container["tags"]:
                    close_category = category[0]
                    valid_classification = classification
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
                return phantom.APP_ERROR

            # close MDE incident with container close tags
            if not self._handle_update_incident(incident_id=incident["incidentId"],
                                                status="Resolved",
                                                comment="Incident closed from SOAR",
                                                category=close_category,
                                                tags=incident_tags + container_tags):
                self.error_print("Failed to close incident", incident["incidentId"])
                return phantom.APP_ERROR
            return phantom.APP_SUCCESS

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

    def _sdi(self, input_dictionary: dict) -> str:
        # incidentId
        if input_dictionary.get("incidentId", False):
            random.Random().seed(input_dictionary["incidentId"])

        # alertId
        if input_dictionary.get("alertId", False):
            random.Random().seed(input_dictionary["alertId"])

        return str(uuid.UUID(version=4, int=random.Random().getrandbits(128)))

    # ---------------------- #
    # DATA OBJECT PROCESSING #
    # ---------------------- #

    def initialize(self):
        # Load the state in initialize, use it to store data that needs to be accessed across actions
        self.state = self.load_state()

        self.config = SettingsParser(settings=self.get_config(), defaults=self.config_defaults)
        self.debug_print("self.config.values:", self.config.values)

        for resource in self.resources:
            token = self.state.get("tokens", {}).get(resource, False)
            if isinstance(token, str):
                self.debug_print(f"token[{resource}] (str):", token)
            if isinstance(token, AuthenticationToken):
                self.debug_print(f"token[{resource}] (AuthenticationToken):", token.token)
                try:
                    encrypted_token = self.state["tokens"][resource].get("token", "")
                    self.debug_print("encrypted_token:", encrypted_token)
                    raw_token = encryption_helper.decrypt(encrypted_token, self.asset_id)
                    self.debug_print("raw_token", raw_token)
                    self.tokens[resource].token = raw_token
                except Exception as e:
                    self.debug_print("Failed to decrypt authentication token:", parse_exception_message(e))

        if not self.state.get('live_response', False):
            self.state['live_response'] = {}

        if not self.state.get('isolated_devices', False):
            self.state['isolated_devices'] = []

        return phantom.APP_SUCCESS

    def finalize(self):
        for resource in self.resources:
            if self.tokens[resource].token:
                try:
                    self.state["tokens"][resource] = encryption_helper.encrypt(self.tokens[resource].token,
                                                                               self.asset_id)
                except Exception as e:
                    self.debug_print("Failed to encrypt authentication token:", parse_exception_message(e))

        # Save any active live response actions
        self.state['live_response'] = {k: v for k, v in self.live_response.items()}

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self.state)
        self.save_progress(f"Action execution time: {datetime.now() - self._action_start_time} seconds")
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
