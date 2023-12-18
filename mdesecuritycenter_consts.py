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
    CALL PAGE SIZE LIMITS
"""
LIST_INCIDENTS_LIMIT = 100
LIST_ALERTS_LIMIT = 10000

"""
    INCIDENTS
"""
INCIDENT_LIST = "/api/incidents"
INCIDENT_SINGLE = "/api/incidents/{incident_id}"

"""
    ALERTS
"""
ALERT_LIST = "/api/alerts"
ALERT_SINGLE = "/api/alerts/{alert_id}"
ALERT_BATCH_UPDATE = "/api/alerts/batchUpdate"
ALERT_CREATE = "/api/alerts/CreateAlertByReference"
ALERT_FILES = "/api/alerts/{alert_id}/files"

"""
    LIVE RESPONSE
"""
LIVE_RESPONSE_LIST_LIBRARY = "/api/libraryfiles"
LIVE_RESPONSE_ACTIONS = "/api/machineactions"
LIVE_RESPONSE_ACTION = "/api/machineactions/{action_id}"
LIVE_RESPONSE_RUN_ACTION = "/api/machines/{machine_id}/runliveresponse"
LIVE_RESPONSE_ACTION_RESULT = "/api/machineactions/{action_id}/GetLiveResponseResultDownloadLink(index={command_index})"

"""
    INVESTIGATIONS
"""
INVESTIGATION_LIST = "/api/investigations"
INVESTIGATION_SINGLE = "/api/investigations/{investigation_id}"
INVESTIGATION_START = "/api/machines/{machine_id}/startInvestigation"
INVESTIGATION_COLLECT_PACKAGE = "/api/machines/{machine_id}/collectInvestigationPackage"

"""
    MACHINES
"""
MACHINE_LIST_ACTIONS = "/api/machineactions/{machine_id}"
MACHINE_ISOLATE = "/api/machines/{machine_id}/isolate"
MACHINE_UNISOLATE = "/api/machines/{machine_id}/unisolate"

"""
    FILES
"""
FILE_INFO = "/api/files/{file_id}"
FILE_STATS = "/api/files/{file_id}/stats"
FILE_QUARANTINE = "/api/machines/{machine_id}/StopAndQuarantineFile"
