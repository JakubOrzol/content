import pytest
import dateparser
from datetime import datetime, timedelta, timezone

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from Cyjax import INCIDENTS_LAST_FETCH_KEY, DATE_FORMAT, MAX_INCIDENTS_TO_FETCH, SEVERITIES, Client, main, cyjax_sdk, \
    convert_severity, convert_date_to_string, get_incidents_last_fetch_timestamp, test_module as module_test, \
    get_incident_command, fetch_incidents


def test_constants():
    assert 'last_fetch' == INCIDENTS_LAST_FETCH_KEY
    assert '%Y-%m-%dT%H:%M:%SZ' == DATE_FORMAT
    assert 50 == MAX_INCIDENTS_TO_FETCH
    assert ['low', 'medium', 'high', 'critical'] == SEVERITIES

def test_convert_severity():
    assert 1 == convert_severity('low')
    assert 1 == convert_severity('Low')
    assert 2 == convert_severity('Medium')
    assert 2 == convert_severity('medium')
    assert 3 == convert_severity('HIGH')
    assert 3 == convert_severity('high')
    assert 4 == convert_severity('Critical')
    assert 4 == convert_severity('critical')

def test_convert_date_to_string():
    date = datetime(2020, 6, 17, 15, 20, 10, tzinfo=timezone.utc)
    assert '2020-06-17T15:20:10Z' == convert_date_to_string(date)

def test_get_incidents_last_fetch_timestamp(mocker):
    date = datetime(2020, 6, 17, 15, 20, 10, tzinfo=timezone.utc)
    timestamp = int(date.timestamp())

    mocker.patch.object(demisto, 'getLastRun', return_value={
        INCIDENTS_LAST_FETCH_KEY: str(timestamp)
    })

    last_timestamp = get_incidents_last_fetch_timestamp()
    assert isinstance(last_timestamp, int)
    assert timestamp == last_timestamp

def test_get_incidents_last_fetch_timestamp_on_fist_fetch(mocker):
    three_days_ago = datetime.now() - timedelta(days=3)
    three_days_ago_timestamp = int(three_days_ago.timestamp())

    mocker.patch.object(demisto, 'getLastRun', return_value={})

    last_timestamp = get_incidents_last_fetch_timestamp()
    assert isinstance(last_timestamp, int)
    assert three_days_ago_timestamp <= last_timestamp

def test_test_module(mocker):
    client = mocker.MagicMock()
    client.test_connection.return_value = (True, '')

    assert 'ok' == module_test(client)

    client.test_connection.return_value = (False, 'Invalid Api Key')
    assert 'Could not connect to Cyjax API (Invalid Api Key)' == module_test(client)

def test_get_incident_command(mocker):
    client = mocker.MagicMock()
    mocked_incident = MockContainer.get_one_incident(12345)
    client.fetch_incident_by_id.return_value = mocked_incident

    command_response = get_incident_command(client, {'id': 12345})
    assert isinstance(command_response, dict)
    assert 'Type' in command_response
    assert 'ContentsFormat' in command_response
    assert 'Contents' in command_response
    assert 'ReadableContentsFormat' in command_response
    assert 'HumanReadable' in command_response
    assert 'EntryContext' in command_response
    assert EntryType.NOTE == command_response.get('Type')
    assert EntryFormat.JSON == command_response.get('ContentsFormat')
    assert EntryFormat.MARKDOWN == command_response.get('ReadableContentsFormat')
    assert mocked_incident == command_response.get('Contents')


def test_fetch_incidents(mocker):
    last_run = 1603616400

    incidnet_mock_one = MockContainer.get_one_incident(100, '2020-10-25T10:00:00+0000')  # 1603620000
    incidnet_mock_two = MockContainer.get_one_incident(101, '2020-10-25T13:00:00+0000')  # 1603630800

    client = mocker.MagicMock()
    client.fetch_incidents.return_value = [incidnet_mock_one, incidnet_mock_two]

    result = fetch_incidents(client, last_run, MAX_INCIDENTS_TO_FETCH)
    assert isinstance(result, tuple)
    next_run, incidents = result
    assert {'last_fetch': 1603630800} == next_run

    expected_incidents = [
        {
            'name': incidnet_mock_one['title'],
            'details': incidnet_mock_one['description'],
            'occurred': convert_date_to_string(datetime.fromtimestamp(1603620000)),
            'rawJSON': json.dumps(incidnet_mock_one),
            'severity': convert_severity(incidnet_mock_one['severity']),
        },
        {
            'name': incidnet_mock_two['title'],
            'details': incidnet_mock_two['description'],
            'occurred': convert_date_to_string(datetime.fromtimestamp(1603630800)),
            'rawJSON': json.dumps(incidnet_mock_two),
            'severity': convert_severity(incidnet_mock_two['severity']),
        },
    ]
    assert isinstance(incidents, list)
    assert expected_incidents[0] == incidents[0]
    assert 2 == len(incidents)
    assert expected_incidents == incidents


''' COMMAND FUNCTIONS TEST'''
def test_fetch_incidents_main_command_call(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'api_key': 'test-api-key',
    })
    mocker.patch.object(demisto, 'getLastRun', return_value={
        INCIDENTS_LAST_FETCH_KEY: '1592407210'
    })

    mocked_incident = MockContainer.get_one_incident(100)
    incident_date = dateparser.parse(mocked_incident['last_update'])
    incident_timestamp = int(incident_date.timestamp())

    ir_mock = mocker.MagicMock()
    ir_mock.list.return_value = [mocked_incident]

    mocker.patch('Cyjax.cyjax_sdk.IncidentReport', return_value=ir_mock)
    mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'setLastRun')

    main()

    assert demisto.incidents.call_count == 1
    assert demisto.setLastRun.call_count == 1

    demisto.incidents.assert_called_with([{
            'name': mocked_incident['title'],
            'details': mocked_incident['description'],
            'occurred': convert_date_to_string(incident_date),
            'rawJSON': json.dumps(mocked_incident),
            'severity': convert_severity(mocked_incident['severity']),
        }])

    demisto.setLastRun.assert_called_with({'last_fetch': incident_timestamp})


def test_get_incident_main_command_call(mocker):
    mocker.patch.object(demisto, 'args', return_value={
        'id': '100',
    })

    mocked_incident = MockContainer.get_one_incident(100)
    ir_mock = mocker.MagicMock()
    ir_mock.one.return_value = mocked_incident
    mocker.patch('Cyjax.cyjax_sdk.IncidentReport', return_value=ir_mock)
    mocker.patch.object(demisto, 'command', return_value='cyjax-get-incident')
    mocker.patch.object(demisto, 'results')

    main()
    assert demisto.results.call_count == 1
    result = demisto.results.call_args[0][0]

    assert isinstance(result, dict)
    assert 'Type' in result
    assert 'ContentsFormat' in result
    assert 'Contents' in result
    assert 'ReadableContentsFormat' in result
    assert 'HumanReadable' in result
    assert 'EntryContext' in result
    assert EntryType.NOTE == result.get('Type')
    assert EntryFormat.JSON == result.get('ContentsFormat')
    assert EntryFormat.MARKDOWN == result.get('ReadableContentsFormat')
    assert mocked_incident == result.get('Contents')

    mocker.patch('Cyjax.cyjax_sdk.IncidentReport', side_effect=Exception('Not found'))
    main()
    assert demisto.results.call_count == 2
    assert demisto.results.call_args[0][0] is None


def test_test_module_main_command_call(mocker):
    ir_mock = mocker.MagicMock()
    ir_mock.list.return_value = []

    mocker.patch('Cyjax.cyjax_sdk.IncidentReport', return_value=ir_mock)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results')

    main()
    assert demisto.results.call_count == 1
    assert demisto.results.call_args[0][0] == 'ok'

    mocker.patch('Cyjax.cyjax_sdk.IncidentReport', side_effect=Exception('Server not responding'))

    main()
    assert demisto.results.call_count == 2
    assert demisto.results.call_args[0][0] == 'Could not connect to Cyjax API (Server not responding)'


class MockContainer:

    @staticmethod
    def get_one_incident(incident_id=None, date=None):
        now = datetime.now()

        if date is None:
            date = "2020-10-27T11:42:55+0000"

        if incident_id is None:
            incident_id = int(now.timestamp())

        return {
            'id': incident_id,
            'title': 'Test incident {}-{}'.format(int(now.timestamp()), incident_id),
            'description': 'this is Ir description',
            "severity": "medium",
            "source": "https://www.test.jakub.com/test",
            "last_update": date,
            "source_evaluation": "always-reliable",
            "impacts": {
                "others": "minimal-impact",
                "retail": "minimal-impact"
            },
            "tags": [
                "email address",
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
