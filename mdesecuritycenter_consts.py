# File: mdesecuritycenter_consts.py
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

"""
    INCIDENTS
"""
# https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-incident
INCIDENT_LIST = "/api/incidents"
INCIDENT_SINGLE = "/api/incidents/{incident_id}"

"""
    ALERTS
"""
# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/alerts
ALERT_LIST = "/api/alerts"
ALERT_SINGLE = "/api/alerts/{alert_id}"
ALERT_BATCH_UPDATE = "/api/alerts/batchUpdate"
ALERT_CREATE = "/api/alerts/CreateAlertByReference"
ALERT_FILES = "/api/alerts/{alert_id}/files"

"""
    LIVE RESPONSE
"""
# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/list-library-files
LIVE_RESPONSE_LIST_LIBRARY = "/api/libraryfiles"
# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-live-response
LIVE_RESPONSE_RUN_SCRIPT = "/api/machines/{machine_id}/runliveresponse"
# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-live-response-result
LIVE_RESPONSE_GET_RESULT = "/api/machineactions/{action_id}/GetLiveResponseResultDownloadLink(index={command_index})"

"""
    INVESTIGATIONS
"""
# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/investigation
INVESTIGATION_LIST = "/api/investigations"
INVESTIGATION_SINGLE = "/api/investigations/{investigation_id}"
INVESTIGATION_START = "/api/machines/{machine_id}/startInvestigation"
# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/collect-investigation-package
INVESTIGATION_COLLECT_PACKAGE = "/api/machines/{machine_id}/collectInvestigationPackage"

"""
    MACHINES
"""
# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-machineaction-object
MACHINE_LIST_ACTIONS = "/api/machineactions/{machine_id}"
# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/isolate-machine
MACHINE_ISOLATE = "/api/machines/{machine_id}/isolate"
# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/unisolate-machine
MACHINE_UNISOLATE = "/api/machines/{machine_id}/unisolate"

"""
    FILES
"""
# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/stop-and-quarantine-file
FILE_INFO = "/api/files/{file_id}"
FILE_STATS = "/api/files/{file_id}/stats"
FILE_QUARANTINE = "/api/machines/{machine_id}/StopAndQuarantineFile"
