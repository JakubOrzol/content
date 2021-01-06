import pytest
import dateparser
from datetime import datetime, timedelta, timezone

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from Cyjax import INCIDENTS_LAST_FETCH_KEY, DATE_FORMAT, MAX_INCIDENTS_TO_FETCH, SEVERITIES, Client, main, cyjax_sdk, \
    convert_severity, convert_date_to_string, get_incidents_last_fetch_timestamp, get_incident_custom_fields, \
    test_module as module_test, get_incident_command, fetch_incidents


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


def test_get_incident_custom_fields(mocker):
    cs = {'impacts': 'testy',
         'incidentreportid': 1234,
         'reportcontent': 'test test test test',
         'source-eveluation': 'always-reliable'}

    incident = {'id': 123,
                'details': 'details',
                'type': 'Cyjax Incident Report',
                'brand': 'Cyjax',
                'CustomFields': cs}
    mocker.patch.object(demisto, 'incident', return_value=incident)

    custom_fields = get_incident_custom_fields()
    assert custom_fields == cs

    assert 1234 == get_incident_custom_fields('incidentreportid')

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
    assert demisto.results.call_args[0][0] == {'Contents': 'Incident with id=100 not found',
                                               'ContentsFormat': 'text',
                                               'Type': EntryType.WARNING}


def test_get_my_report_main_command_call(mocker):
    mocker.patch.object(demisto, 'args', return_value={
        'id': '12',
    })

    mocked_my_report = MockContainer.get_one_my_report(12)
    mr_mock = mocker.MagicMock()
    sdk_mock = mocker.MagicMock()
    mr_mock.one.return_value = mocked_my_report
    sdk_mock.MyReport.return_value = mr_mock
    mocker.patch('Cyjax.cyjax_sdk', return_value=mr_mock)
    mocker.patch.object(demisto, 'command', return_value='cyjax-get-my-report')
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
    # assert mocked_my_report == result.get('Contents') #todo: mock MyReports when updating SDK

    mocker.patch('Cyjax.cyjax_sdk.MyReport', side_effect=Exception('Not found'))
    main()
    assert demisto.results.call_count == 2
    assert demisto.results.call_args[0][0] == {'Contents': 'MyReport with id=12 not found',
                                               'ContentsFormat': 'text',
                                               'Type': EntryType.WARNING}


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


def test_get_incident_report_id_command_call(mocker):
    cs = {'impacts': 'testy',
         'incidentreportid': 1234,
         'reportcontent': 'test test test test',
         'source-eveluation': 'always-reliable'}

    incident = {'id': 123,
                'details': 'details',
                'type': 'Cyjax Incident Report',
                'brand': 'Cyjax',
                'CustomFields': cs}

    mocker.patch.object(demisto, 'incident', return_value=incident)
    mocker.patch.object(demisto, 'command', return_value='cyjax-get-incident-report-id')
    mocker.patch.object(demisto, 'results')

    main()
    assert demisto.results.call_count == 1
    assert demisto.results.call_args[0][0] == {'Type': 1,
                                               'ContentsFormat': 'text',
                                               'Contents': 'Cyjax Incident Report ID = 1234'}


def test_get_incident_indicators_command_call(mocker):
    mocker.patch.object(demisto, 'args', return_value={
        'id': '3000',
    })
    iocs = MockContainer.get_indicator_iocs()

    mocker.patch('Cyjax.cyjax_sdk.IncidentReport.indicators', return_value=iocs)
    mocker.patch.object(demisto, 'command', return_value='cyjax-get-incident-indicators')
    mocker.patch.object(demisto, 'results')

    main()

    assert demisto.results.call_count == 1
    assert demisto.results.call_args[0][0] == {
        'Type': EntryType.NOTE,
        'ContentsFormat': EntryFormat.JSON,
        'Contents': iocs,
        'ReadableContentsFormat': EntryFormat.MARKDOWN,
        'HumanReadable': tableToMarkdown('Incident Report Indicators:', iocs, headerTransform=pascalToSpace),
        'EntryContext': {
            'Cyjax.IncidentIndicators': createContext(iocs, removeNull=True),
        }
    }


def test_get_incident_indicators_command_call_not_found(mocker):
    mocker.patch.object(demisto, 'args', return_value={
        'id': '3001',
    })

    mocker.patch('Cyjax.cyjax_sdk.IncidentReport.indicators', return_value=[])
    mocker.patch.object(demisto, 'command', return_value='cyjax-get-incident-indicators')
    mocker.patch.object(demisto, 'results')

    main()

    assert demisto.results.call_count == 1
    assert demisto.results.call_args[0][0] == {
        'Type': EntryType.NOTE,
        'ContentsFormat': EntryFormat.JSON,
        'Contents': [],
        'ReadableContentsFormat': EntryFormat.MARKDOWN,
        'HumanReadable': tableToMarkdown('Incident Report Indicators:', [], headerTransform=pascalToSpace),
        'EntryContext': {
            'Cyjax.IncidentIndicators': createContext([], removeNull=True),
        }
    }


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
                "United Kingdom",
                "Germany",
                "Poland"
            ],
            "techniques": [
                    "Input Capture",
                    "Signed Script Proxy Execution",
                    "Obfuscated Files or Information",
                    "Fallback Channels"
                ],
            "software": [
                    "Cobalt Strike",
                    "Pay2Key"
            ],
            "ioc": [
                {
                    "type": "IPv4",
                    "industry_type": [
                        "Government",
                        "Military",
                        "IT",
                        "Politics",
                        "Extremism"
                    ],
                    "ttp": None,
                    "value": "51.9.76.199",
                    "handling_condition": "GREEN",
                    "discovered_at": "2020-12-17T17:01:27+0000",
                    "description": "Malicious IP",
                    "source": "https://website.domain.com/report/incident/view?id=100"
                },
                {
                    "type": "domain",
                    "industry_type": [
                        "Government",
                        "Military",
                        "IT",
                        "Politics",
                        "Extremism"
                    ],
                    "ttp": None,
                    "value": "malicious-domain.com",
                    "handling_condition": "GREEN",
                    "discovered_at": "2020-12-17T17:01:27+0000",
                    "description": "Malicious domain found",
                    "source": "https://website.domain.com/report/incident/view?id=101"
                },
                {
                    "type": "file",
                    "industry_type": [
                        "Government",
                        "Military",
                        "IT",
                        "Politics",
                        "Extremism"
                    ],
                    "ttp": None,
                    "value": {
                        "hashes": {
                            "MD5": "2b67b7d14d1479dd7935f326d05a34d2"
                        }
                    },
                    "handling_condition": "GREEN",
                    "discovered_at": "2020-12-17T17:01:27+0000",
                    "description": "MD5 ioc description",
                    "source": "https://website.domain.com/report/incident/view?id=102"
                }
            ]
        }

    @staticmethod
    def get_one_my_report(report_id=None, date=None):
        now = datetime.now()

        if date is None:
            date = "2020-10-27T11:42:55+0000"

        if report_id is None:
            report_id = int(now.timestamp())

        return {
            'id': report_id,
            'title': 'Test my report {}-{}'.format(int(now.timestamp()), report_id),
            'description': 'this is my report description',
            "last_update": date,
        }

    @staticmethod
    def get_indicator_iocs():
        return [
            {
                "type": "IPv6",
                "industry_type": [
                    "maritime",
                    "Law Enforcement"
                ],
                "value": "2606:4700:4700::1111",
                "handling_condition": "GREEN",
                "discovered_at": "2020-12-23T10:01:12+0000",
                "description": "Report with IP iocs",
                "source": "https://website.domain.com/report/incident/view?id=105"
            },
            {
                "type": "IPv6",
                "industry_type": [
                    "maritime",
                    "Law Enforcement"
                ],
                "value": "2001:19f0:6401:b3d:5400:2ff:fe5a:fb9f",
                "handling_condition": "GREEN",
                "discovered_at": "2020-12-23T10:01:12+0000",
                "description": "Report with IP iocs",
                "source": "https://website.domain.com/report/incident/view?id=105"
            },
            {
                "type": "FileHash-SHA256",
                "industry_type": [
                    "Pharmaceutical",
                    "Mining"
                ],
                "value": "0018c726f6b9cb74816a4463d03ef6d52c5bc8595e1b8a7a28b51e7ea4f18a90",
                "handling_condition": "GREEN",
                "discovered_at": "2020-12-23T09:58:15+0000",
                "description": "File Ioc added to this report",
                "source": "https://website.domain.com/report/incident/view?id=105"
            },
            {
                "type": "FileHash-MD5",
                "industry_type": [
                    "Pharmaceutical",
                    "Mining"
                ],
                "value": "e0d123e5f316bef78bfdf5a008837577",
                "handling_condition": "GREEN",
                "discovered_at": "2020-12-23T09:58:15+0000",
                "description": "File Ioc added to this report",
                "source": "https://website.domain.com/report/incident/view?id=105"
            },
            {
                "type": "FileHash-SHA1",
                "industry_type": [
                    "Pharmaceutical",
                    "Mining"
                ],
                "value": "546bf4fc684c5d1e17b204a28c795a414124335b6ef7cbadf52ae8fbadcb2a4a",
                "handling_condition": "GREEN",
                "discovered_at": "2020-12-23T09:58:15+0000",
                "description": "File Ioc added to this report",
                "source": "https://website.domain.com/report/incident/view?id=105"
            },
        ]
