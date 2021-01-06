import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
#


import time
import json
import datetime
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast

import cyjax as cyjax_sdk

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

INCIDENTS_LAST_FETCH_KEY = 'last_fetch'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
SEVERITIES = ['low', 'medium', 'high', 'critical']


''' CLIENT CLASS '''


class Client(object):
    """Client class to interact with the Cyjax API using Cyjax SDK"""

    def __init__(self, base_url, api_key, proxies=None, verify_ssl=True):
        self.__base_url = base_url
        self.__api_key = api_key
        self.__proxies = proxies
        self.__verify_ssl = verify_ssl
        self._set_sdk()

    def _set_sdk(self) -> None:
        """Set Cyjax SDK
        :return: None
        """
        cyjax_sdk.api_key = self.__api_key

        if self.__base_url:
            cyjax_sdk.api_url = self.__base_url

        if self.__proxies:
            cyjax_sdk.proxy_settings = self.__proxies

        if self.__verify_ssl is False:
            cyjax_sdk.verify_ssl = False

    def test_connection(self) -> Tuple[bool, str]:
        """Test connection to the Cyjax API using Cyjax SDK. Call incident report list API, and check if it's valid list

        :return: A tuple with connection result and the error message if test failed.
        :rtype: ``Tuple(bool, str)``
        """
        result = False
        error_msg = 'Not responding'

        try:
            reports = list(cyjax_sdk.IncidentReport().list(since=datetime.timedelta(minutes=5)))
            result = True
        except Exception as e:
            error_msg = str(e)

        return result, error_msg

    def fetch_incidents(self, last_run: int, limit: int) -> list:
        """
        Fetch Incident Reports from Cyjax.

        :type last_run: ``int``
        :param last_run: The last run timestamp, since when to fetch the incidents from.

        :type limit: ``int``
        :param limit: Max number of incidents to fetch by one call

        :return: The list of Incident Reports
        :rtype: list
        """
        since = datetime.datetime.utcfromtimestamp(last_run)

        incidnet_reports = cyjax_sdk.IncidentReport().list(since=since)
        # incidnet_reports = [self.fetch_incident_by_id(9999901)]

        return incidnet_reports

    def fetch_incident_by_id(self, incident_id: int) -> Optional[Dict[str, Any]]:
        """
        Fetch one Incident report by ID from Cyjax.

        :type incident_id: ``int``
        :param incident_id: The incident report ID.

        :return: The Incident Report dict or None
        :rtype: Dict[str, Any]
        """
        # now = datetime.datetime.now()
        # test_id = str(int(now.timestamp()))[-6:]
        #
        # incident = {
        #         'id': test_id,
        #         'title': 'Test incident {}-{}'.format(now.strftime(DATE_FORMAT), test_id),
        #         'description': '<h3>Tthis is Ir description, incident date is: {}</h3>\r\nThis is another line <i>hehehe</i><p>testeststsetse <img src=\"/report/incident/download-file?id=1111\" alt=\"Image\" /></p>'.format(now.strftime(DATE_FORMAT)),
        #         "severity": "medium",
        #         "source": "https://www.test.jakub.com/test",
        #         "last_update": "2020-10-27T11:42:55+0000",
        #         "source_evaluation": "always-reliable",
        #         "impacts": {
        #             "others": "minimal-impact",
        #             "retail": "minimal-impact"
        #         },
        #         "tags": [
        #             "Amazon",
        #             "Corporate espionage",
        #             "email address",
        #             "EMEA",
        #             "Europe",
        #             "global",
        #             "inside threat",
        #             "Leaks",
        #             "phone number",
        #             "UK",
        #             "unauthorised access"
        #         ],
        #         "countries": [
        #             "United Kingdom", "Poland", "Germany", "Russia"
        #         ],
        #         "techniques": [
        #             "Input Capture",
        #             "Signed Script Proxy Execution",
        #             "Obfuscated Files or Information",
        #             "Fallback Channels"
        #         ],
        #         "software": [
        #             "Cobalt Strike",
        #             "Pay2Key"
        #         ],
        #         "ioc": [
        #             {
        #                 "type": "domain",
        #                 "industry_type": [
        #                     "Government",
        #                     "Military",
        #                     "IT",
        #                     "Politics",
        #                     "Extremism"
        #                 ],
        #                 "ttp": None,
        #                 "value": "krasil-anthony.icu",
        #                 "handling_condition": "GREEN",
        #                 "discovered_at": "2020-12-17T17:01:27+0000",
        #                 "description": "[UPDATE - 17.12.2020] PyMicropsia - new modular Trojan linked to @AridViper",
        #                 "source": "https://cymon.co/report/incident/view?id=69668"
        #             },
        #             {
        #                 "type": "domain",
        #                 "industry_type": [
        #                     "Government",
        #                     "Military",
        #                     "IT",
        #                     "Politics",
        #                     "Extremism"
        #                 ],
        #                 "ttp": None,
        #                 "value": "lordblackwood.club",
        #                 "handling_condition": "GREEN",
        #                 "discovered_at": "2020-12-17T17:01:27+0000",
        #                 "description": "[UPDATE - 17.12.2020] PyMicropsia - new modular Trojan linked to @AridViper",
        #                 "source": "https://cymon.co/report/incident/view?id=69668"
        #             },
        #             {
        #                 "type": "file",
        #                 "industry_type": [
        #                     "Government",
        #                     "Military",
        #                     "IT",
        #                     "Politics",
        #                     "Extremism"
        #                 ],
        #                 "ttp": None,
        #                 "value": {
        #                     "hashes": {
        #                         "MD5": "2b67b7d14d1479dd7935f326d05a34d2"
        #                     }
        #                 },
        #                 "handling_condition": "GREEN",
        #                 "discovered_at": "2020-12-17T17:01:27+0000",
        #                 "description": "[UPDATE - 17.12.2020] PyMicropsia - new modular Trojan linked to @AridViper",
        #                 "source": "https://cymon.co/report/incident/view?id=69668"
        #             }
        #         ]
        #     }

        try:
            incident = cyjax_sdk.IncidentReport().one(incident_id)  # todo: uncomment this
        except Exception as e:
            incident = None  # Incident not found

        return incident

    def fetch_my_report_by_id(self, report_id: int) -> Optional[Dict[str, Any]]:
        """
        Fetch one instance of my report by ID from Cyjax.

        :type report_id: ``int``
        :param report_id: The my report ID.

        :return: The My Report dict or None
        :rtype: ``Dict[str, Any]``
        """
        try:
            my_report = cyjax_sdk.MyReport().one(report_id)
        except Exception as e:
            my_report = None  # MyReport not found

        return my_report

    def fetch_incident_report_indicators(self, report_id: int) -> List[Dict[str, Any]]:
        """
        Fetch list of indicators that are assigned to the incident report

        :type report_id: ``int``
        :param report_id: The incident report ID.

        :return: The list of indicators
        :rtype: ``List[Dict[str, Any]]``
        """
        # indicators = [
        #     {
        #         "type": "IPv6",
        #         "industry_type": [
        #             "maritime",
        #             "Law Enforcement"
        #         ],
        #         "value": "2606:4700:4700::1111",
        #         "handling_condition": "GREEN",
        #         "discovered_at": "2020-12-23T10:01:12+0000",
        #         "description": "Report with IP iocs",
        #         "source": "http://threat-dev.cyjax.com/report/incident/view?id=65268"
        #     },
        #     {
        #         "type": "IPv6",
        #         "industry_type": [
        #             "maritime",
        #             "Law Enforcement"
        #         ],
        #         "value": "2001:19f0:6401:b3d:5400:2ff:fe5a:fb9f",
        #         "handling_condition": "GREEN",
        #         "discovered_at": "2020-12-23T10:01:12+0000",
        #         "description": "Report with IP iocs",
        #         "source": "http://threat-dev.cyjax.com/report/incident/view?id=65268"
        #     },
        #     {
        #         "type": "FileHash-SHA256",
        #         "industry_type": [
        #             "Pharmaceutical",
        #             "Mining"
        #         ],
        #         "value": "0018c726f6b9cb74816a4463d03ef6d52c5bc8595e1b8a7a28b51e7ea4f18a90",
        #         "handling_condition": "GREEN",
        #         "discovered_at": "2020-12-23T09:58:15+0000",
        #         "description": "File Ioc added to this report",
        #         "source": "http://threat-dev.cyjax.com/report/incident/view?id=65267"
        #     },
        #     {
        #         "type": "FileHash-MD5",
        #         "industry_type": [
        #             "Pharmaceutical",
        #             "Mining"
        #         ],
        #         "value": "e0d123e5f316bef78bfdf5a008837577",
        #         "handling_condition": "GREEN",
        #         "discovered_at": "2020-12-23T09:58:15+0000",
        #         "description": "File Ioc added to this report",
        #         "source": "http://threat-dev.cyjax.com/report/incident/view?id=65267"
        #     },
        #     {
        #         "type": "FileHash-SHA1",
        #         "industry_type": [
        #             "Pharmaceutical",
        #             "Mining"
        #         ],
        #         "value": "546bf4fc684c5d1e17b204a28c795a414124335b6ef7cbadf52ae8fbadcb2a4a",
        #         "handling_condition": "GREEN",
        #         "discovered_at": "2020-12-23T09:58:15+0000",
        #         "description": "File Ioc added to this report",
        #         "source": "http://threat-dev.cyjax.com/report/incident/view?id=65267"
        #     },
        # ]

        try:
            indicators = cyjax_sdk.IncidentReport().indicators(report_id)  # todo: IMPLEMENT THIS
        except Exception as e:
            indicators = None  # Indicators not found

        return indicators


''' HELPER FUNCTIONS '''


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
    """Converts an XSOAR argument to a timestamp (seconds from epoch)"""

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():
        # timestamp is a str containing digits - we just convert it to int
        return int(arg)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "3 days", etc
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f'Invalid date: {arg_name}')

        return int(date.timestamp())
    if isinstance(arg, (int, float)):
        # Convert to int if the input is a float
        return int(arg)
    raise ValueError(f'Invalid date: "{arg_name}"')


def convert_severity(severity: str) -> int:
    """Maps Cyjax severity to Cortex XSOAR severity

    Converts the Cyjax severity level ('low', 'medium', 'high', 'critical') to Cortex XSOAR incident severity (1 to 4)
    for mapping.

    :type severity: ``str``
    :param severity: severity as returned from the Cyjax API (str)

    :return: Cortex XSOAR Severity (1 to 4)
    :rtype: ``int``
    """
    return {
        'low': 1,
        'medium': 2,
        'high': 3,
        'critical': 4
    }[severity.lower()]


def convert_date_to_string(date_object) -> str:
    """Convert datetime object to datetime string in xsoar format
    :type date_object: ``datetime.datetime``
    :param date_object: datetime object to convert

    :return: date time as string
    :rtype: ``str``
    """
    return date_object.strftime(DATE_FORMAT)


def get_incidents_last_fetch_timestamp() -> int:
    """Get the last incidents_fetch timestamp. Check if incidents were ever fetched before,
    if not find the timestamp for the first fetch.

    :return: Incidents last fetch timestamp
    :rtype: ``int``
    """
    last_fetch_timestamp = demisto.getLastRun().get(INCIDENTS_LAST_FETCH_KEY, None)

    # Check if incidents were ever fetched before
    if last_fetch_timestamp is None:
        # How much time before the first fetch to retrieve incidents
        first_fetch_time = arg_to_timestamp(
            arg=demisto.params().get('first_fetch', '3 days'),
            arg_name='First fetch time',
            required=True
        )
        last_fetch_timestamp = first_fetch_time

    return int(last_fetch_timestamp)


def text_message(message: str, entry_type=None):
    """Return dict with options to display message as text

    :type message: ``str``
    :param message: The message to be rendered

    :type entry_type: ``str``
    :param entry_type: The entry type, @See EntryType

    :return: A dict with result options that is then passed to ``return_results``,
    :rtype: ``dict``
    """
    if entry_type is None:
        entry_type = EntryType.NOTE

    return {
        'Type': entry_type,
        'ContentsFormat': EntryFormat.TEXT,
        'Contents': message,
    }


def warning_message(message: str):
    """Return dict with options to display message as warning text
    :type message: ``str``
    :param message: The message to be rendered as warning

    :return: A dict with result options that is then passed to ``return_results``,
    :rtype: ``dict``
    """
    return text_message(message, EntryType.WARNING)


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication

    :type client: ``Client``
    :param client: Instance of Client class.

    :return: The test result
    :rtype: ``str``
    """
    (result, error_msg) = client.test_connection()

    if result:
        return 'ok'
    else:
        return 'Could not connect to Cyjax API ({})'.format(error_msg)


def say_hello_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """helloworld-say-hello command: Returns Hello {somename}"""
    name = args.get('name', None)
    if not name:
        raise ValueError('name not specified')

    result = 'Hello {}'.format(name)

    readable_output = f'## {result}'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='hello',
        outputs_key_field='',
        outputs=result
    )


def get_from_context(field: str):
    """Get field from current demisto context

    :type field: ``str``
    :param field: The field name

    :return: field value from the context
    :rtype: Any
    """
    return demisto.get(demisto.context(), field)


def get_incident_custom_fields(field=None):
    """Get current incident CustomField, if field is given get this field value from custom fields.

    :type field: ``str``
    :param field: The field name

    :return: field value from the context
    :rtype: Any
    """
    result = None
    incident = demisto.incident()

    if incident:
        custom_fields = incident.get('CustomFields')

        if custom_fields:
            demisto.info(json.dumps(custom_fields))
            if field is None:
                result = custom_fields
            elif field in custom_fields:
                result = custom_fields.get(field)

    return result


''' COMMAND FUNCTIONS '''


def fetch_incidents(client: Client, last_run: int, limit: int) -> Tuple[Dict[str, int], List[dict]]:
    """Fetch Incident Reports from Cyjax API.
    This function retrieves new alerts every interval (default is 1 minute).

    :type client: ``Client``
    :param client: Instance of Client class.

    :type last_run: ``int``
    :param last_run: The last fetch run timestamp

    :type limit: ``int``
    :param limit: Max number of incidents to fetch by one call

    :return: A tuple containing two elements:
            next_run (``Dict[str, int]``): Contains the timestamp that will be
                    used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR
    :rtype: ``Tuple[Dict[str, int], List[dict]]``
    """
    incidents = []  # type:List
    incident_reports = client.fetch_incidents(last_run, limit)

    for incident_report in incident_reports:
        incident_date = dateparser.parse(incident_report['last_update'])
        incident_timestamp = int(incident_date.timestamp())

        incident = {
            'name': incident_report['title'],
            'details': incident_report['description'],
            'occurred': convert_date_to_string(incident_date),
            'rawJSON': json.dumps(incident_report),
            'severity': convert_severity(incident_report['severity']),
        }
        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_timestamp > last_run:
            last_run = incident_timestamp

    next_run = {INCIDENTS_LAST_FETCH_KEY: last_run}
    return next_run, incidents


def get_incident_command(client: Client, args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Get incident report by ID

    :type client: ``Client``
    :param Client: The client

    :type args: ``dict``
    :param args: all command arguments, usually passed from ``demisto.args()``.

    :return: A dict with result options that is then passed to ``return_results``,
    :rtype: ``dict``
    """
    incident_id = args.get('id', None)
    if not incident_id:
        raise ValueError('ID not specified')

    incident = client.fetch_incident_by_id(int(incident_id))

    if incident:
        return {
            'Type': EntryType.NOTE,
            'ContentsFormat': EntryFormat.JSON,
            'Contents': incident,
            'ReadableContentsFormat': EntryFormat.MARKDOWN,
            'HumanReadable': tableToMarkdown('Incident:', incident, headerTransform=pascalToSpace),
            'EntryContext': {
                'Cyjax.Incident(val.ID && val.ID === obj.ID)': createContext(incident, removeNull=True),
            }
        }
    return warning_message('Incident with id={} not found'.format(incident_id))


def get_incident_report_id_command() -> Optional[Dict[str, Any]]:
    """Get current incident report ID

    :return: A dict with result options that is then passed to ``return_results``,
    :rtype: ``dict``
    """
    incidnet_report_id = get_incident_custom_fields('incidentreportid')

    if incidnet_report_id:
        return text_message('Cyjax Incident Report ID = {}'.format(incidnet_report_id))

    return warning_message('Current incident is not Cyjax Incident Report')


def get_my_report_command(client: Client, args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Get my report by ID

    :type client: ``Client``
    :param Client: The client

    :type args: ``dict``
    :param args: all command arguments, usually passed from ``demisto.args()``.

    :return: A dict with result options that is then passed to ``return_results``,
    :rtype: ``dict``
    """
    my_report_id = args.get('id', None)
    if not my_report_id:
        raise ValueError('ID not specified')

    my_report = client.fetch_my_report_by_id(int(my_report_id))

    if my_report:
        return {
            'Type': EntryType.NOTE,
            'ContentsFormat': EntryFormat.JSON,
            'Contents': my_report,
            'ReadableContentsFormat': EntryFormat.MARKDOWN,
            'HumanReadable': tableToMarkdown('My Report:', my_report, headerTransform=pascalToSpace),
            'EntryContext': {
                'Cyjax.MyReport(val.ID && val.ID === obj.ID)': createContext(my_report, removeNull=True),
            }
        }

    return warning_message('MyReport with id={} not found'.format(my_report_id))


def get_incident_indicators_command(client: Client, args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Get indicators from Cyjax incident report. Check if incident has any indicators assigned,
    if so call Cyjax API to get this indicators.

    :type client: ``Client``
    :param Client: The client

    :type args: ``dict``
    :param args: all command arguments, usually passed from ``demisto.args()``.

    :return: A dict with result options that is then passed to ``return_results``,
    :rtype: ``dict``
    """
    incident_id = args.get('id', None)

    # Id in argument not given, try to get it from current incident context.
    if not incident_id:
        incident_id = get_incident_custom_fields('incidentreportid')

    if not incident_id:
        raise ValueError('ID not specified')

    indicators = client.fetch_incident_report_indicators(incident_id)

    return {
        'Type': EntryType.NOTE,
        'ContentsFormat': EntryFormat.JSON,
        'Contents': indicators,
        'ReadableContentsFormat': EntryFormat.MARKDOWN,
        'HumanReadable': tableToMarkdown('Incident Report Indicators:', indicators, headerTransform=pascalToSpace),
        'EntryContext': {
            'Cyjax.IncidentIndicators': createContext(indicators, removeNull=True),
        }
    }


def indicator_sighting_command(client: Client, args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Get sighting of indicator

    :type client: ``Client``
    :param Client: The client

    :type args: ``dict``
    :param args: all command arguments, usually passed from ``demisto.args()``.

    :return: A dict with result options that is then passed to ``return_results``,
    :rtype: ``dict``
    """
    value = args.get('value', None)

    if not value:
        raise ValueError('Value not specified')

    indicator_sighting = {'id': 1234, 'name': 'tester', 'abba': 'babba', 'value': value}

    return {
        'Type': EntryType.NOTE,
        'ContentsFormat': EntryFormat.JSON,
        'Contents': indicator_sighting,
        'ReadableContentsFormat': EntryFormat.MARKDOWN,
        'HumanReadable': tableToMarkdown('Incident Report Indicators:', indicator_sighting,
                                         headerTransform=pascalToSpace),
        'EntryContext': {
            'Cyjax.IndicatorSighting(val.value && val.value === obj.value)': createContext(indicator_sighting, removeNull=True),
        }
    }


def search_threat_actor_command(client: Client, args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Search threat actor by name

    :type client: ``Client``
    :param Client: The client

    :type args: ``dict``
    :param args: all command arguments, usually passed from ``demisto.args()``.

    :return: A dict with result options that is then passed to ``return_results``,
    :rtype: ``dict``
    """
    name = args.get('name', None)

    if not name:
        raise ValueError('Name not specified')

    threat_actors = [{'id': 100, 'name': 'Bob', 'threat': 'actor'},
                     {'id': 101, 'name': 'Troy', 'threat': 'actor'},
                     {'id': 102, 'name': 'Michael', 'threat': 'actor'}]

    return {
        'Type': EntryType.NOTE,
        'ContentsFormat': EntryFormat.JSON,
        'Contents': threat_actors,
        'ReadableContentsFormat': EntryFormat.MARKDOWN,
        'HumanReadable': tableToMarkdown('Incident Report Indicators:', threat_actors,
                                         headerTransform=pascalToSpace),
        'EntryContext': {
            'Cyjax.ThreatActors(val.id && val.id === obj.id)': createContext(threat_actors, removeNull=True),
        }
    }


def get_threat_actor_command(client: Client, args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Get threat actor by name

    :type client: ``Client``
    :param Client: The client

    :type args: ``dict``
    :param args: all command arguments, usually passed from ``demisto.args()``.

    :return: A dict with result options that is then passed to ``return_results``,
    :rtype: ``dict``
    """
    name = args.get('name', None)

    if not name:
        raise ValueError('Name not specified')

    threat_actor = {'id': 500, 'name': 'Hans Zimmer', 'threat': 'SINGLE'}

    return {
        'Type': EntryType.NOTE,
        'ContentsFormat': EntryFormat.JSON,
        'Contents': threat_actor,
        'ReadableContentsFormat': EntryFormat.MARKDOWN,
        'HumanReadable': tableToMarkdown('Incident Report Indicators:', threat_actor,
                                         headerTransform=pascalToSpace),
        'EntryContext': {
            'Cyjax.ThreatActors(val.id && val.id === obj.id)': createContext(threat_actor, removeNull=True),
        }
    }


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions """

    api_key = demisto.params().get('apikey')
    base_url = demisto.params().get('url')
    verify_ssl = not demisto.params().get('insecure', False)
    proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)

    demisto.info(f' ----------- *********** ----------- '
                 f'CYJAX Command being called is {demisto.command()}')  # todo: REMOVE THAT LATER

    try:

        client = Client(
            base_url=base_url,
            api_key=api_key,
            proxies=proxies,
            verify_ssl=verify_ssl)

        if demisto.command() == 'test-module':
            return_results(test_module(client))

        elif demisto.command() == 'fetch-incidents':
            last_fetch_timestamp = get_incidents_last_fetch_timestamp()  # type:int
            limit = min(MAX_INCIDENTS_TO_FETCH, int(demisto.params().get('max_fetch', MAX_INCIDENTS_TO_FETCH)))
            next_run, incidents = fetch_incidents(client, last_fetch_timestamp, limit)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'cyjax-get-incident':
            return_results(get_incident_command(client, demisto.args()))

        elif demisto.command() == 'cyjax-get-incident-report-id':
            return_results(get_incident_report_id_command())

        elif demisto.command() == 'cyjax-get-incident-indicators':
            return_results(get_incident_indicators_command(client, demisto.args()))

        elif demisto.command() == 'cyjax-get-my-report':
            return_results(get_my_report_command(client, demisto.args()))

        elif demisto.command() == 'cyjax-indicator-sighting':
            return_results(indicator_sighting_command(client, demisto.args()))

        elif demisto.command() == 'cyjax-search-threat-actor':
            return_results(search_threat_actor_command(client, demisto.args()))

        elif demisto.command() == 'cyjax-get-threat-actor':
            return_results(get_threat_actor_command(client, demisto.args()))

        elif demisto.command() == 'cyjax-say-hello':
            return_results(say_hello_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
