import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
SEVERITIES = ['Low', 'Medium', 'High', 'Critical']

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API"""

    def say_hello(self, name: str) -> str:
        """Returns 'Hello {name}'

        :type name: ``str``
        :param name: name to append to the 'Hello' string

        :return: string containing 'Hello {name}'
        :rtype: ``str``
        """

        return f'Hello {name}'


''' HELPER FUNCTIONS '''


''' COMMAND FUNCTIONS '''



''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get('apikey')
    base_url = urljoin(demisto.params()['url'], '/api/v1')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_timestamp(
        arg=demisto.params().get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    # Using assert as a type guard (since first_fetch_time is always an int when required=True)
    assert isinstance(first_fetch_time, int)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {
            'Authorization': f'Bearer {api_key}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, first_fetch_time)
            return_results(result)

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            alert_status = demisto.params().get('alert_status', None)
            alert_type = demisto.params().get('alert_type', None)
            min_severity = demisto.params().get('min_severity', None)

            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_results = arg_to_int(
                arg=demisto.params().get('max_fetch'),
                arg_name='max_fetch',
                required=False
            )
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch_time,
                alert_status=alert_status,
                min_severity=min_severity,
                alert_type=alert_type
            )

            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to crate
            demisto.incidents(incidents)

        elif demisto.command() == 'ip':
            default_threshold_ip = int(demisto.params().get('threshold_ip', '65'))
            return_results(ip_reputation_command(client, demisto.args(), default_threshold_ip))

        elif demisto.command() == 'domain':
            default_threshold_domain = int(demisto.params().get('threshold_domain', '65'))
            return_results(domain_reputation_command(client, demisto.args(), default_threshold_domain))

        elif demisto.command() == 'helloworld-say-hello':
            return_results(say_hello_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-search-alerts':
            return_results(search_alerts_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-get-alert':
            return_results(get_alert_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-update-alert-status':
            return_results(update_alert_status_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-scan-start':
            return_results(scan_start_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-scan-status':
            return_results(scan_status_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-scan-results':
            return_results(scan_results_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
