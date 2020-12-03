from typing import Callable, Dict, Iterator

import demistomock as demisto
from CommonServerPython import *

INTERNAL_MODULES_BRANDS = ['Scripts', 'Builtin', 'testmodule']
ENABLED = 'active'
DISABLED = 'disabled'


def prepare_filter_list(args: Dict) -> List[Callable[[Dict], bool]]:
    filter_list = [lambda x: x.get('brand') not in INTERNAL_MODULES_BRANDS]
    if 'brand' in args:
        filter_brands = argToList(args['brand'])
        filter_list.append(lambda x: str(x.get('brand')) in filter_brands)
    if filter_enabled := args.get('is_enabled'):
        filter_enabled = argToBoolean(filter_enabled)
        filter_state = ENABLED if filter_enabled else DISABLED
        filter_list.append(lambda x: x.get('state') == filter_state)
    return filter_list


def filter_instances(modules: Dict, filter_list: List[Callable[[Dict], bool]]) -> Iterator[Dict]:
    for instance, config in modules.items():
        if all(map(lambda x: x(config), filter_list)):
            config['name'] = instance
            yield config


def main():
    try:
        filter_list = prepare_filter_list(demisto.args())
        context_config = list(filter_instances(demisto.getModules(), filter_list))
        return_results(CommandResults(
            outputs=context_config,
            outputs_prefix='Modules'
        ))
    except Exception as error:
        return_error(str(error), error)


if __name__ in ['__main__', 'builtins']:
    main()
