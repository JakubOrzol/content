import pytest
from GetInstances import *


WITH_SYSTEM_FILTER = {}
WITH_BRAND_FILTER = {'brand': 'EWS v2, splunk'}
WITH_IS_ENABLED_FILTER = {'is_enabled': 'true'}
WITH_ALL_FILTERS = {'brand': 'EWS v2, splunk', 'is_enabled': 'true'}


def load_json_file(path):
    with open(path, 'r') as json_file:
        json_string = json_file.read()
    return json.loads(json_string)


class TestPrepareFilterList:
    def test_without_any_filter(self):
        filters = prepare_filter_list(WITH_SYSTEM_FILTER)
        assert len(filters) == 1
        assert filters[0]({'brand': 'EWS v2'})
        assert not filters[0]({'brand': 'Scripts'})
        assert not filters[0]({'brand': 'Builtin'})
        assert not filters[0]({'brand': 'testmodule'})

    def test_without_brand_filter(self):
        filters = prepare_filter_list(WITH_BRAND_FILTER)
        assert len(filters) == 2
        assert filters[1]({'brand': 'EWS v2'})
        assert filters[1]({'brand': 'splunk'})
        assert not filters[1]({'brand': 'other'})

    def test_without_enabled_filter(self):
        filters = prepare_filter_list(WITH_IS_ENABLED_FILTER)
        assert len(filters) == 2
        assert filters[1]({'state': 'active'})
        assert not filters[1]({'state': 'disabled'})

    def test_all(self):
        filters = prepare_filter_list(WITH_ALL_FILTERS)
        assert len(filters) == 3
        assert filters[0]({'brand': 'EWS v2'})
        assert not filters[0]({'brand': 'Scripts'})
        assert not filters[0]({'brand': 'Builtin'})
        assert not filters[0]({'brand': 'testmodule'})
        assert filters[1]({'brand': 'EWS v2'})
        assert filters[1]({'brand': 'splunk'})
        assert not filters[1]({'brand': 'other'})
        assert filters[2]({'state': 'active'})
        assert not filters[2]({'state': 'disabled'})


data_test_filter_instances = [
    (WITH_SYSTEM_FILTER, 'system_filter'),
    (WITH_BRAND_FILTER, 'brand_filter'),
    (WITH_IS_ENABLED_FILTER, 'is_enabled_filter'),
    (WITH_ALL_FILTERS, 'all_filters')
]


@pytest.mark.parametrize('filer_args, filter_type', data_test_filter_instances)
def test_filter_instances(filer_args, filter_type):
    modules = load_json_file('test_data/raw_modules.json')
    filters = prepare_filter_list(filer_args)
    output_instances = list(filter_instances(modules, filters))
    assert load_json_file(f'test_data/modules_with_{filter_type}.json') == output_instances
