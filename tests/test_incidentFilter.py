# test_incidentFilter.py

from modules.AzureSentinel.incidentfilter import IncidentFilter
from core.functions import getConf
import pytest

cfg = getConf()
class AzureIncident:
    def __init__(self, products, severity, title, entities=None):
        template = {'properties':
                    {'additionalData':
                     {'alertProductNames': []},
                     'severity': '',
                     'title': '',
                     'incidentNumber': 9999}}
        template['properties']['additionalData']['alertProductNames'] = products
        template['properties']['severity'] = severity
        template['properties']['title'] = title
        if entities:
            template['entities'] = entities
        self.incident = template

class EntityTemplate:
    def __init__(self, kind, properties):
        entity_template = {
            'kind': kind,
            'properties': properties
        }
        self.entity = entity_template

@pytest.fixture
def incidentFilter():
    filter = IncidentFilter(cfg)
    return filter

def test_applicationFilter_input_validation(incidentFilter):
    func = incidentFilter.checkProductFilter

    with pytest.raises(TypeError):
        func(['A', 'B', 'C', 'D'], 'B', mode='inclusion')
        func(['B'], 'B', mode='exclusion')
        func(['B'], 123, mode='exclusion')

def test_applicationFilter_inclusion(incidentFilter):
    func = incidentFilter.checkProductFilter

    assert func(['A', 'B', 'C', 'D'], ['B'], mode='inclusion') is True
    assert func(['A', 'B', 'C', 'D'], ['E'], mode='inclusion') is False
    assert func(['A', 'B', 'C', 'D'], ['A', 'B'], mode='inclusion') is True
    assert func(['A', 'B', 'C', 'D'], ['A', 'E'], mode='inclusion') is True
    assert func(['A', 'B', 'C', 'D'], ['E', 'F'], mode='inclusion') is False

def test_applicationFilter_exclusion(incidentFilter):
    func = incidentFilter.checkProductFilter

    assert func(['B'], ['B'], mode='exclusion') is True
    assert func(['A', 'B'], ['B'], mode='exclusion') is False
    assert func(['A', 'B'], ['B'], mode='exclusion') is False
    assert func(['A', 'B'], ['C'], mode='exclusion') is False
    assert func(['A', 'B'], ['A', 'B'], mode='exclusion') is True
    assert func(['A', 'B'], ['A', 'C'], mode='exclusion') is False
    assert func(['A', 'B'], ['C', 'D'], mode='exclusion') is False
    assert func(['A', 'B'], ['A', 'B', 'C'], mode='exclusion') is False

def test_severityFilter(incidentFilter):
    func = incidentFilter.checkSeverityFilter

    # str to str match
    assert func('High', 'High') is True
    assert func('High', 'Low') is False

    # list to str match
    assert func(['High', 'Medium', 'Low'], 'Low') is True
    assert func(['High', 'Medium', 'Low'], 'Informational') is False

    # input format validation test
    with pytest.raises(TypeError):
        func(['High', 'Medium', 'Low'], ['Informational'])
        func(['High', 'Medium', 'Low'], ['Low'])

    # Remove tests if case_sensititvity is added.
    assert func('high', 'High') is False
    assert func('High', 'high') is False

def test_titleFilter_strings(incidentFilter):
    func = incidentFilter.checkStringFilter

    # str to substring matches
    assert func('abcd', 'abcd') is True
    assert func('abc', 'abcd') is True
    assert func('abcde', 'abcd') is False
    assert func('dcba', 'abcd') is False

    # cases insensitivity test
    assert func('aBCd', 'abcD') is True
    assert func('aBc', 'abcd') is True
    assert func('AbcdE', 'abCd') is False
    assert func('DcbA', 'abcD') is False

    # substring list to string test
    assert func(['Anne', 'Bob', 'Carl', 'David'], 'Anne Apple') is True
    assert func(['Anne', 'Bob', 'Carl', 'David'], 'Andrew Apple') is False

    # input validation test
    with pytest.raises(TypeError):
        func('abcd', ['abcd'])
        func(['Anne', 'Bob', 'Carl', 'David'], ['Anne Apple'])

def test_titleFilter_regex(incidentFilter):
    func = incidentFilter.checkStringFilter

    # regex match testing
    assert func([{"regex": ".*"}], 'Carl') is True
    assert func([{"regex": "Carl"}, 'Bob'], "Carl") is True
    assert func([{"regex": "Carl"}, 'Carl'], "Bob") is False
    assert func([{"regex": ".*'the bear'.*"}, 'Carl'], "Bob 'the bear' Barker") is True
    assert func([{"regex": ".*'the bear'.*"}, 'Carl'], "Bob 'the boar' Barker") is False
    assert func([{"regex": ".*'the bear'.*"}, {"regex": ".*'the boar'.*"}], "Bob 'the boar' Barker") is True

    with pytest.raises(TypeError):
        func([{"regex": ["Carl"]}, 'Carl'], "Bob")

def test_titleFilter_contains_all(incidentFilter):
    func = incidentFilter.checkStringFilter

    assert func([{"contains_all": ['A']}], 'ABCD') is True
    assert func([{"contains_all": ['A']}], 'BCD') is False
    assert func([{"contains_all": ['A', 'B']}], 'ABCD') is True
    assert func([{"contains_all": ['A', 'B']}], 'ACD') is False

    assert func([{"contains_all": ['A', 'B']}, {"contains_all": ['C', 'D']}], 'CDEF') is True
    assert func([{"contains_all": ['A', 'B']}, {"contains_all": ['C', 'D']}], 'ADEF') is False

def test_checkEntityFilter_input(incidentFilter):
    func = incidentFilter.checkEntityFilter
    entitity_inclusions = [
        {'entity': {
            'kind': 'Host',
            'properties': {
                'hostName': 'test123'
            }
        }}
    ]
    with pytest.raises(TypeError):
        func({'test': 'value'}, EntityTemplate('Host', {'hostName': 'test123'}).entity)
        func([{'test': 'value'}], EntityTemplate('Host', {'hostName': 'test123'}).entity)
        func(entitity_inclusions, ['string'])
        func([], [])
        func('', '')
        func([], '')

def test_checkEntityFilter(incidentFilter):
    func = incidentFilter.checkEntityFilter

    entitity_inclusions = [
        {'entity': {
            'kind': 'Host',
            'properties': {
                'hostName': 'test123'
            }
        }},
        {'entity': {
            'kind': 'File',
            'properties': {
                'fileName': 'test123.txt'
            }
        }},
        {'entity': {
            'kind': 'File',
            'properties': {
                'fileName': ['test456.txt', 'test321.txt']
            }
        }},
        {'entity': {
            'kind': 'Account',
            'properties': {
                'accountName': [{'regex': 'test.*'}]
            }
        }}
    ]

    # Test exclusions setup
    assert func(entitity_inclusions, EntityTemplate('Host', {'hostName': 'test123'}).entity) is True
    assert func(entitity_inclusions, EntityTemplate('File', {'hostName': 'test123'}).entity) is False
    assert func(entitity_inclusions, EntityTemplate('File', {'fileName': 'test123.txt'}).entity) is True
    assert func(entitity_inclusions, EntityTemplate('File', {'fileName': 'test456.txt'}).entity) is True
    assert func(entitity_inclusions, EntityTemplate('File', {'fileName': 'test321.txt'}).entity) is True
    assert func(entitity_inclusions, EntityTemplate('Account', {'accountName': 'test123456.txt'}).entity) is True

    # Exclusion should fail if not all entities match
    assert func(entitity_inclusions, EntityTemplate('File', {'fileName': 'test456.txt'}).entity, mode='exclusion') is False
    assert func(entitity_inclusions, EntityTemplate('File', {'fileName': 'test321.txt'}).entity, mode='exclusion') is False

    # Exclusion should succeed if all entities match
    assert func(entitity_inclusions, [EntityTemplate('Host', {'hostName': 'test123'}).entity,
                                      EntityTemplate('File', {'fileName': 'test123.txt'}).entity,
                                      EntityTemplate('File', {'fileName': 'test321.txt'}).entity,
                                      EntityTemplate('Account', {'accountName': 'test123456.txt'}).entity], mode='exclusion') is True

def test_checkCustomDetails(incidentFilter):
    func = incidentFilter.checkCustomDetailsFilter

    with pytest.raises(TypeError):
        func({'SOCalert': 'True'}, {'SOCalert': ['True']})
        func([{'SOCalert': 'True'}], [{'SOCalert': ['True']}])
        func('SOCalert', [{'SOCalert': ['True']}])

    assert func({'SOCalert': 'True'}, [{'SOCalert': ['True']}]) is True
    assert func({'SOCalert': 'True'}, [{'SOCalert': ['False']}]) is False
    assert func({'SOCalert': 'False'}, [{'SOCalert': ['True']}]) is False
    assert func({'SOCalert': 'False'}, [{'NOCalert': ['False']}]) is False
    assert func({'SOCalert': 'True'}, [{'SOCalert': ['True', 'False', 'False', 'False', 'False']}]) is True
    assert func({'SOCalert': 'True'}, [{'SOCalert': ['False', 'False', 'False', 'False', 'False']}]) is False

def test_checkInclusion(incidentFilter):
    func = incidentFilter.checkFilter
    incidentFilter.inclusion_config = [{'Inclusion Name': {'product': 'Defender',
                                                        'severity': 'High',
                                                        'title': 'UserAccount'}},
                                    {'Second inclusion': {'product': 'Sentinel',
                                                          'severity': ['High', 'Medium'],
                                                          'title': 'SEC123'}},
                                    {'product inclusion': {'product': 'Sentinel'}},
                                    {'severity inclusion': {'severity': 'Unique'}},
                                    {'title inclusion': {'title': 'Unique'}}]

    assert func(AzureIncident(['Defender'], 'High', 'Suspicious UserAccount Detected').incident, '')[0] is True
    assert func(AzureIncident(['Defender'], 'High', 'Suspicious AdminAccount Detected').incident, '')[0] is False
    assert func(AzureIncident(['Defender'], 'Medium', 'Suspicious UserAccount Detected').incident, '')[0] is False
    assert func(AzureIncident(['Defender Extended'], 'High', 'Suspicious UserAccount Detected').incident, '')[0] is False
    assert func(AzureIncident(['Sentinel'], 'Undetermined', 'Suspicious AdminAccount Detected').incident, '')[0] is True
    assert func(AzureIncident(['Defender'], 'Unique', 'Suspicious AdminAccount Detected').incident, '')[0] is True
    assert func(AzureIncident(['Defender'], 'Undetermined', 'Unique Account Detected').incident, '')[0] is True

def test_checkExclusion(incidentFilter):
    func = incidentFilter.checkFilter
    incidentFilter.exclusion_config = [{'Exclusion Name': {'product': 'Defender',
                                                        'severity': 'High',
                                                        'title': 'UserAccount'}},
                                    {'Second exclusion': {'product': 'Sentinel',
                                                          'severity': ['High', 'Medium'],
                                                          'title': 'SEC123'}},
                                    {'product exclusion': {'product': 'Sentinel'}},
                                    {'severity exclusion': {'severity': 'Unique'}},
                                    {'title exclusion': {'title': 'Unique'}}]

    assert func(AzureIncident(['Defender'], 'High', 'Suspicious UserAccount Detected').incident, '', mode='exclusion')[0] is True
    assert func(AzureIncident(['Defender'], 'High', 'Suspicious AdminAccount Detected').incident, '', mode='exclusion')[0] is False
    assert func(AzureIncident(['Defender'], 'Medium', 'Suspicious UserAccount Detected').incident, '', mode='exclusion')[0] is False
    assert func(AzureIncident(['Defender Extended'], 'High', 'Suspicious UserAccount Detected').incident, '', mode='exclusion')[0] is False
    assert func(AzureIncident(['Sentinel'], 'Undetermined', 'Suspicious AdminAccount Detected').incident, '', mode='exclusion')[0] is True
    assert func(AzureIncident(['Defender'], 'Unique', 'Suspicious AdminAccount Detected').incident, '', mode='exclusion')[0] is True
    assert func(AzureIncident(['Defender'], 'Undetermined', 'Unique Account Detected').incident, '', mode='exclusion')[0] is True

def test_filterIncident(incidentFilter):
    func = incidentFilter.filterIncident
    incidentFilter.inclusion_config = [{'Inclusion Name': {'product': 'Defender',
                                                        'severity': ['High', 'Medium', 'Low'],
                                                        'title': 'UserAccount'}},
                                    {'product inclusion': {'product': 'Sentinel'}},
                                    {'severity inclusion': {'severity': 'Unique'}},
                                    {'title inclusion': {'title': 'Unique'}}]

    incidentFilter.exclusion_config = [{'severity exclusion': {'severity': 'Informational'}},
                                    {'title exclusion': {'title': 'SEC'}}]

    assert func(AzureIncident(['Defender'], 'High', 'Unique UserAccount Detected').incident)[0] is True
    assert func(AzureIncident(['Defender'], 'Medium', 'Unique UserAccount Detected').incident)[0] is True
    assert func(AzureIncident(['Defender'], 'Low', 'Unique UserAccount Detected').incident)[0] is True
    assert func(AzureIncident(['Sentinel'], 'Informational', 'Unique UserAccount Detected').incident)[0] is False
    assert func(AzureIncident(['MCAS'], 'Unique', 'Unique UserAccount Detected').incident)[0] is True
    assert func(AzureIncident(['Sentinel'], 'Unique', 'SEC1234: Unique UserAccount Detected').incident)[0] is False
    assert func(AzureIncident(['Defender for 365'], 'Unknown', 'Unknown').incident)[0] is False

    # Add functions to test the message log
