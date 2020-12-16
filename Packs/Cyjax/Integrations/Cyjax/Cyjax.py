import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import time
import json
import datetime
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast

import cyjax

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

    def __init__(self, base_url, api_key, proxies=None):
        self.__base_url = base_url
        self.__api_key = api_key
        self.__proxies = proxies
        self._set_sdk()

    def _set_sdk(self) -> None:
        """Set Cyjax SDK
        :return: None
        """
        cyjax.api_key = self.__api_key

        if self.__base_url:
            cyjax.api_url = self.__base_url

        if self.__proxies:
            cyjax.proxy_settings = self.__proxies


    def say_hello(self, name: str) -> str:
        """Returns 'Hello {name}'

        :type name: ``str``
        :param name: name to append to the 'Hello' string

        :return: string containing 'Hello {name}'
        :rtype: ``str``
        """
        return f'Hello {name}'

    def test_connection(self) -> Tuple[bool, str]:
        """Test connection to the Cyjax API using Cyjax SDK.

        :return: A tuple with connection result and the error message if test failed.
        :rtype: ``Tuple(bool, str)``
        """
        result = False
        error_msg = 'Not responding'

        try:
            reports = cyjax.IncidentReport().list(since=datetime.timedelta(minutes=5))
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

        # incidnet_reports = cyjax.IncidentReport().list(since=since) #todo: uncomment this
        incidnet_reports = [self.fetch_incident_by_id(1)]

        return incidnet_reports

    def fetch_incident_by_id(self, incident_id: int) -> Optional[Dict[str, Any]]:
        """
        Fetch one Incident report by ID from Cyjax.

        :type incident_id: ``int``
        :param incident_id: The incident report ID.

        :return: The Incident Report dict or None
        :rtype: Dict[str, Any]
        """
        now = datetime.datetime.now()
        test_id = int(now.timestamp())

        incident = {
                'id': test_id,
                'title': 'Test incident {}-{}'.format(now.strftime(DATE_FORMAT), test_id),
                'description': 'this is Ir description, incident date is: {}'.format(now.strftime(DATE_FORMAT)),
                "severity": "medium",
                "source": "https://www.test.jakub.com/test",
                "last_update": "2020-10-27T11:42:55+0000",
                "source_evaluation": "always-reliable",
                "impacts": {
                    "others": "minimal-impact",
                    "retail": "minimal-impact"
                },
                "tags": [
                    "Amazon",
                    "Corporate espionage",
                    "email address",
                    "EMEA",
                    "Europe",
                    "global",
                    "inside threat",
                    "Leaks",
                    "phone number",
                    "UK",
                    "unauthorised access"
                ],
                "countries": [
                    "United Kingdom"
                ],
                "techniques": [],
                "software": [],
                "ioc": []
            }

        return incident

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


''' COMMAND FUNCTIONS '''


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

    result = client.say_hello(name)

    readable_output = f'## {result}'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='hello',
        outputs_key_field='',
        outputs=result
    )


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
        # incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_timestamp > last_run:
            last_run = incident_timestamp

    demisto.info('------------------------------------ Setting incidents {}'.format(incidents))

    next_run = {INCIDENTS_LAST_FETCH_KEY: last_run}
    return next_run, incidents


def get_incident_command(client: Client, args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Get incident report by ID

    :type client: ``Client``
    :param Client: The client

    :type args: ``dict``
    :param args: all command arguments, usually passed from ``demisto.args()``.

    :return: A ``CommandResults`` object that is then passed to ``return_results``,
    :rtype: ``CommandResults``
    """
    incident_id = args.get('id', None)
    if not incident_id:
        raise ValueError('ID not specified')

    incident = client.fetch_incident_by_id(incident_id)

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
    return None


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions """

    api_key = demisto.params().get('apikey')
    base_url = demisto.params().get('url')
    proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)

    demisto.info(f' ----------- *********** ----------- '
                  f'CYJAX Command being called is {demisto.command()}') #todo: REMOVE THAT LATER

    try:

        client = Client(
            base_url=base_url,
            api_key=api_key,
            proxies=proxies)

        if demisto.command() == 'test-module':
            return_results(test_module(client))

        elif demisto.command() == 'cyjax-fetch-incidents': #todo: DELETE THAT AFTER DEVELOPING
            last_fetch_timestamp = get_incidents_last_fetch_timestamp()  # type:int
            limit = min(MAX_INCIDENTS_TO_FETCH, int(demisto.params().get('max_fetch', MAX_INCIDENTS_TO_FETCH)))
            next_run, incidents = fetch_incidents(client, last_fetch_timestamp)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'fetch-incidents':
            last_fetch_timestamp = get_incidents_last_fetch_timestamp()  # type:int
            limit = min(MAX_INCIDENTS_TO_FETCH, int(demisto.params().get('max_fetch', MAX_INCIDENTS_TO_FETCH)))
            next_run, incidents = fetch_incidents(client, last_fetch_timestamp, limit)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'cyjax-get-incident':
            return_results(get_incident_command(client, demisto.args()))

        elif demisto.command() == 'cyjax-say-hello':
            return_results(say_hello_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
