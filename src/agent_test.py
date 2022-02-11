from forta_agent import FindingSeverity, FindingType, create_transaction_event
from agent import provide_handle_transaction, initialize
from constants import EOA_TRANSACTION_COUNT_FILTER
from web3_mock import Web3Mock,CONTRACT_ADDRESS,EOA_ADDRESS,EOA_ADDRESS2

import datetime

w3 = Web3Mock()

class TestPhishingAgent:
    def test_returns_empty_findings_if_invalid_transaction(self):
        tx_event = create_transaction_event(
            {'receipt': {'status': 0}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

    def test_returns_empty_findings_if_zero_data_size(self):
        tx_event = create_transaction_event(
            {'receipt': {'status': 1},
            'transaction': {'data': '0x',
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

    def test_returns_empty_findings_if_incorrect_data_size(self):
        tx_event = create_transaction_event(
            {'receipt': {'status': 1},
            'transaction': {'data': '0x095ea7b300000000000000000000000004c90c198b2eff55716079bc06d7ccc4aa4d7512ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa',
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

    def test_returns_empty_findings_if_incorrect_method(self):
        tx_event = create_transaction_event(
            {'receipt': {'status': 1},
            'transaction': {'data': '0x1234567800000000000000000000000004c90c198b2eff55716079bc06d7ccc4aa4d7512ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

    def test_returns_empty_findings_if_zero_amount_transferFrom(self):
        tx_event = create_transaction_event(
            {'receipt': {'status': 1},
            'transaction': {'data': '0x23b872dd000000000000000000000000806603f47d3ea5bdbc9e4ad5d07562fa670020430000000000000000000000004fbf7701b3078b5bed6f3e64df3ae09650ee7de50000000000000000000000000000000000000000000000000000000000000000',
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

    def test_returns_empty_findings_if_zero_amount_approve(self):
        tx_event = create_transaction_event(
            {'receipt': {'status': 1},
            'transaction': {'data': '0x095ea7b300000000000000000000000004c90c198b2eff55716079bc06d7ccc4aa4d75120000000000000000000000000000000000000000000000000000000000000000',
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

    def test_returns_empty_findings_if_zero_amount_increase_allowance(self):
        tx_event = create_transaction_event(
            {'receipt': {'status': 1},
            'transaction': {'data': '0x3950935100000000000000000000000004c90c198b2eff55716079bc06d7ccc4aa4d75120000000000000000000000000000000000000000000000000000000000000000',
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

    def test_returns_empty_findings_if_contract_address(self):
        tx_event = create_transaction_event(
            {'receipt': {'status': 1},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+CONTRACT_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

    def test_returns_empty_findings_if_EOA_below_threshold(self):
        tx_event = create_transaction_event(
            {'receipt': {'status': 1},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

    def test_returns_empty_findings_if_EOA_above_threshold(self):
        initialize()
        
        CONTRACT1 = "0xfd05d3c7fe2924020620a8be4961bbaa747e6305" 
        CONTRACT2 = "0xfbdca68601f835b27790d98bbb8ec7f05fdeaa9b"
        
        tx_event = create_transaction_event(
            {'receipt': {'status': 1,
                         'transaction_hash': '0x4fdd88d18b0a036edca888bf28b98ef88e63c45f6fe9fc226b4e6cb30a2eda6b'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT1,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

        tx_event = create_transaction_event(
            {'receipt': {'status': 1,
                         'transaction_hash': '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS2[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT2,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

    def test_returns_finding_if_EOA_above_threshold_approve(self):
        initialize()
        
        CONTRACT1 = "0xfd05d3c7fe2924020620a8be4961bbaa747e6305" 
        CONTRACT2 = "0xfbdca68601f835b27790d98bbb8ec7f05fdeaa9b"
        
        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
             'receipt': {'status': 1,
                         'transaction_hash': '0x4fdd88d18b0a036edca888bf28b98ef88e63c45f6fe9fc226b4e6cb30a2eda6b'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT1,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT2,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==1
        finding = next((x for x in findings if x.alert_id == 'PHISHING-SUS-ERC20-EOA-APPROVALS'), None)
        assert finding.description == f'{EOA_ADDRESS.lower()} was granted approvals to 2 ERC-20 contracts'
        assert finding.severity == FindingSeverity.High
        assert finding.type == FindingType.Suspicious
        assert finding.metadata.get('last_contract') == CONTRACT2
        assert finding.metadata.get('last_tx_hash') == '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'
        assert finding.metadata.get('last_victim') == '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'
        assert finding.metadata.get('uniq_approval_contract_count') == 2

    def test_returns_empty_finding_if_EOA_above_threshold_nonsense_function(self):
        initialize()
        
        CONTRACT1 = "0xfd05d3c7fe2924020620a8be4961bbaa747e6305" 
        CONTRACT2 = "0xfbdca68601f835b27790d98bbb8ec7f05fdeaa9b"
        
        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
             'receipt': {'status': 1,
                         'transaction_hash': '0x4fdd88d18b0a036edca888bf28b98ef88e63c45f6fe9fc226b4e6cb30a2eda6b'},
            'transaction': {'data': '0x12345678000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT1,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'},
            'transaction': {'data': '0x12345678000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT2,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0
       
    def test_returns_finding_if_EOA_above_threshold_incAllowance(self):
        initialize()
        
        CONTRACT1 = "0xfd05d3c7fe2924020620a8be4961bbaa747e6305" 
        CONTRACT2 = "0xfbdca68601f835b27790d98bbb8ec7f05fdeaa9b"
        
        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
             'receipt': {'status': 1,
                         'transaction_hash': '0x4fdd88d18b0a036edca888bf28b98ef88e63c45f6fe9fc226b4e6cb30a2eda6b'},
            'transaction': {'data': '0x39509351000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT1,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'},
            'transaction': {'data': '0x39509351000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT2,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==1
        finding = next((x for x in findings if x.alert_id == 'PHISHING-SUS-ERC20-EOA-APPROVALS'), None)
        assert finding.description == f'{EOA_ADDRESS.lower()} was granted approvals to 2 ERC-20 contracts'
        assert finding.severity == FindingSeverity.High
        assert finding.type == FindingType.Suspicious
        assert finding.metadata.get('last_contract') == CONTRACT2
        assert finding.metadata.get('last_tx_hash') == '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'
        assert finding.metadata.get('last_victim') == '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'
        assert finding.metadata.get('uniq_approval_contract_count') == 2
        

    def test_returns_empty_findings_if_EOA_mul_transactions_same_contract(self):
        initialize()
        
        CONTRACT1 = "0xfd05d3c7fe2924020620a8be4961bbaa747e6305" 
         
        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4fdd88d18b0a036edca888bf28b98ef88e63c45f6fe9fc226b4e6cb30a2eda6b'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT1,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT1,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0
        
    def test_returns_finding_if_EOA_above_threshold_and_time_threshold_passed(self):
        initialize()
        
        CONTRACT1 = "0xfd05d3c7fe2924020620a8be4961bbaa747e6305" 
        CONTRACT2 = "0xfbdca68601f835b27790d98bbb8ec7f05fdeaa9b"
        CONTRACT3 = "0xae96ff08771a109dc6650a1bdca62f2d558e40af"
        
        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4fdd88d18b0a036edca888bf28b98ef88e63c45f6fe9fc226b4e6cb30a2eda6b'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT1,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637504449}, #Nov-21-2021
             'receipt': {'status': 1,
                         'transaction_hash': '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT2,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==1

        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1638368449}, #Dec-1-2021
             'receipt': {'status': 1,
                         'transaction_hash': '0x738be3f7a08e118bf01c68db917dcc4bd72e64766f7880daf61861be381fdfc0'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT3,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==1
    
    def test_returns_no_repeat_finding_if_EOA_above_threshold_and_time_threshold_fails(self):
        initialize()
        
        CONTRACT1 = "0xfd05d3c7fe2924020620a8be4961bbaa747e6305" 
        CONTRACT2 = "0xfbdca68601f835b27790d98bbb8ec7f05fdeaa9b"
        CONTRACT3 = "0xae96ff08771a109dc6650a1bdca62f2d558e40af"
        
        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4fdd88d18b0a036edca888bf28b98ef88e63c45f6fe9fc226b4e6cb30a2eda6b'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT1,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637504449}, #Nov-21-2021
             'receipt': {'status': 1,
                         'transaction_hash': '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT2,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==1

        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637590849}, #Nov-22-2021
             'receipt': {'status': 1,
                         'transaction_hash': '0x738be3f7a08e118bf01c68db917dcc4bd72e64766f7880daf61861be381fdfc0'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT3,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

    def test_returns_no_repeat_finding_if_EOA_above_threshold_and_count_threshold_fails(self):
        initialize()
        
        CONTRACT1 = "0xfd05d3c7fe2924020620a8be4961bbaa747e6305" 
        CONTRACT2 = "0xfbdca68601f835b27790d98bbb8ec7f05fdeaa9b"
        
        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4fdd88d18b0a036edca888bf28b98ef88e63c45f6fe9fc226b4e6cb30a2eda6b'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT1,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637504449}, #Nov-21-2021
             'receipt': {'status': 1,
                         'transaction_hash': '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT2,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==1

        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1638368449}, #Dec-1-2021
             'receipt': {'status': 1,
                         'transaction_hash': '0x738be3f7a08e118bf01c68db917dcc4bd72e64766f7880daf61861be381fdfc0'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT2,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

    def test_returns_findings_if_EOA_above_threshold_transaction_vol_below_threshold(self):
        initialize()
        
        CONTRACT1 = "0xfd05d3c7fe2924020620a8be4961bbaa747e6305" 
        CONTRACT2 = "0xfbdca68601f835b27790d98bbb8ec7f05fdeaa9b"
        
        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4fdd88d18b0a036edca888bf28b98ef88e63c45f6fe9fc226b4e6cb30a2eda6b'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT1,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

        for i in range(EOA_TRANSACTION_COUNT_FILTER-1):
            tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4fdd88d18b0a036edca888bf28b98ef88e63c45f6fe9fc226b4e6cb30a2eda6b'},
            'transaction': {'to' : CONTRACT1,
                            'from' : EOA_ADDRESS.lower()}})
            findings = provide_handle_transaction(w3)(tx_event)
            assert len(findings)==0

        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT2,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==1

    def test_returns_findings_if_EOA_above_threshold_transaction_vol_above_threshold(self):
        initialize()
        
        CONTRACT1 = "0xfd05d3c7fe2924020620a8be4961bbaa747e6305" 
        CONTRACT2 = "0xfbdca68601f835b27790d98bbb8ec7f05fdeaa9b"
        
        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4fdd88d18b0a036edca888bf28b98ef88e63c45f6fe9fc226b4e6cb30a2eda6b'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT1,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

        for i in range(EOA_TRANSACTION_COUNT_FILTER):
            tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4fdd88d18b0a036edca888bf28b98ef88e63c45f6fe9fc226b4e6cb30a2eda6b'},
            'transaction': {'to' : CONTRACT1,
                            'from' : EOA_ADDRESS.lower()}})
            findings = provide_handle_transaction(w3)(tx_event)
            assert len(findings)==0

        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT2,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

    def test_returns_finding_if_EOA_transfers_after_approval_finding(self):
        initialize()
        
        CONTRACT1 = "0xfd05d3c7fe2924020620a8be4961bbaa747e6305" 
        CONTRACT2 = "0xfbdca68601f835b27790d98bbb8ec7f05fdeaa9b"
        
        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
             'receipt': {'status': 1,
                         'transaction_hash': '0x4fdd88d18b0a036edca888bf28b98ef88e63c45f6fe9fc226b4e6cb30a2eda6b'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT1,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT2,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==1
        finding = next((x for x in findings if x.alert_id == 'PHISHING-SUS-ERC20-EOA-APPROVALS'), None)
        assert finding.description == f'{EOA_ADDRESS.lower()} was granted approvals to 2 ERC-20 contracts'
        assert finding.severity == FindingSeverity.High
        assert finding.type == FindingType.Suspicious
        assert finding.metadata.get('last_contract') == CONTRACT2
        assert finding.metadata.get('last_tx_hash') == '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'
        assert finding.metadata.get('last_victim') == '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'
        assert finding.metadata.get('uniq_approval_contract_count') == 2

        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'},
            'transaction': {'data': '0x23b872dd000000000000000000000000ebd031016f1a4e316521e78111b99db6a3e29ffc0000000000000000000000004631018f63d5e31680fb53c11c9e1b11f1503e6f0000000000000000000000000000000000000000000002712ec5d5b7e4cd0afc',
                            'to' : CONTRACT2,
                            'from' : EOA_ADDRESS.lower()}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==1
        finding = next((x for x in findings if x.alert_id == 'PHISHING-SUS-ERC20-EOA-TRANSFERS'), None)
        assert finding.description == f'{EOA_ADDRESS.lower()} transferred funds from {CONTRACT2} contract to address 0x4631018f63d5e31680fb53c11c9e1b11f1503e6f'
        assert finding.severity == FindingSeverity.Critical
        assert finding.type == FindingType.Exploit
        assert finding.metadata.get('last_contract') == CONTRACT2
        assert finding.metadata.get('last_tx_hash') == '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'
        assert finding.metadata.get('last_attacker_address') == '0x4631018F63d5E31680FB53C11C9e1B11F1503e6f'.lower()
        assert finding.metadata.get('last_victim') == '0xeBD031016F1a4e316521e78111B99dB6A3e29FFC'.lower()
        
    def test_returns_empty_finding_if_EOA_transfers_after_noapproval_finding(self):
        initialize()
        
        CONTRACT1 = "0xfd05d3c7fe2924020620a8be4961bbaa747e6305" 
        CONTRACT2 = "0xfbdca68601f835b27790d98bbb8ec7f05fdeaa9b"
        
        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
             'receipt': {'status': 1,
                         'transaction_hash': '0x4fdd88d18b0a036edca888bf28b98ef88e63c45f6fe9fc226b4e6cb30a2eda6b'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT1,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'},
            'transaction': {'data': '0x23b872dd000000000000000000000000ebd031016f1a4e316521e78111b99db6a3e29ffc0000000000000000000000004631018f63d5e31680fb53c11c9e1b11f1503e6f0000000000000000000000000000000000000000000002712ec5d5b7e4cd0afc',
                            'to' : CONTRACT2,
                            'from' : EOA_ADDRESS.lower()}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0
       
    def test_returns_empty_finding_if_EOA_transfers_after_approval_finding_incorrect_contract_transfer(self):
        initialize()
        
        CONTRACT1 = "0xfd05d3c7fe2924020620a8be4961bbaa747e6305" 
        CONTRACT2 = "0xfbdca68601f835b27790d98bbb8ec7f05fdeaa9b"
        CONTRACT3 = "0xffffffffffffffffff90d98bbb8ec7f05fdeaa9b"
        
        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
             'receipt': {'status': 1,
                         'transaction_hash': '0x4fdd88d18b0a036edca888bf28b98ef88e63c45f6fe9fc226b4e6cb30a2eda6b'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT1,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT2,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==1

        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'},
            'transaction': {'data': '0x23b872dd000000000000000000000000ebd031016f1a4e316521e78111b99db6a3e29ffc0000000000000000000000004631018f63d5e31680fb53c11c9e1b11f1503e6f0000000000000000000000000000000000000000000002712ec5d5b7e4cd0afc',
                            'to' : CONTRACT3,
                            'from' : EOA_ADDRESS.lower()}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0
        
    def test_returns_empty_finding_if_EOA_transfers_after_approval_finding_but_repeat_within_window(self):
        initialize()
        
        CONTRACT1 = "0xfd05d3c7fe2924020620a8be4961bbaa747e6305" 
        CONTRACT2 = "0xfbdca68601f835b27790d98bbb8ec7f05fdeaa9b"
        
        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
             'receipt': {'status': 1,
                         'transaction_hash': '0x4fdd88d18b0a036edca888bf28b98ef88e63c45f6fe9fc226b4e6cb30a2eda6b'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT1,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT2,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==1
        
        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'},
            'transaction': {'data': '0x23b872dd000000000000000000000000ebd031016f1a4e316521e78111b99db6a3e29ffc0000000000000000000000004631018f63d5e31680fb53c11c9e1b11f1503e6f0000000000000000000000000000000000000000000002712ec5d5b7e4cd0afc',
                            'to' : CONTRACT2,
                            'from' : EOA_ADDRESS.lower()}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==1

        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394277}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4dc690efffffe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'},
            'transaction': {'data': '0x23b872dd000000000000000000000000ebd031016f1a4e316521e78111b99db6a3e29ffc0000000000000000000000004631018f63d5e31680fb53c11c9e1b11f1503e6f0000000000000000000000000000000000000000000002712ec5d5b7e4cd0afc',
                            'to' : CONTRACT2,
                            'from' : EOA_ADDRESS.lower()}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

    def test_returns_finding_if_EOA_transfers_after_approval_finding_but_repeat_outside_window(self):
        initialize()
        
        CONTRACT1 = "0xfd05d3c7fe2924020620a8be4961bbaa747e6305" 
        CONTRACT2 = "0xfbdca68601f835b27790d98bbb8ec7f05fdeaa9b"
        
        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
             'receipt': {'status': 1,
                         'transaction_hash': '0x4fdd88d18b0a036edca888bf28b98ef88e63c45f6fe9fc226b4e6cb30a2eda6b'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT1,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==0

        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'},
            'transaction': {'data': '0x095ea7b3000000000000000000000000'+EOA_ADDRESS[2:].lower()+'00000000000000000000000000000000000000000000000000000000000000ff',
                            'to' : CONTRACT2,
                            'from' : '0xd4e84e1a4907190e3f9718adfbd1f00b0b9be7d8'}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==1
        
        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1637394276}, #Nov-20-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4dc690e799efe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'},
            'transaction': {'data': '0x23b872dd000000000000000000000000ebd031016f1a4e316521e78111b99db6a3e29ffc0000000000000000000000004631018f63d5e31680fb53c11c9e1b11f1503e6f0000000000000000000000000000000000000000000002712ec5d5b7e4cd0afc',
                            'to' : CONTRACT2,
                            'from' : EOA_ADDRESS.lower()}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==1

        tx_event = create_transaction_event(
            {'block' : {'timestamp' : 1638368449}, #Dec-1-2021
            'receipt': {'status': 1,
                         'transaction_hash': '0x4dc690efffffe14ac0f86f35836db557652db252cb234e4fec560ba414c76506'},
            'transaction': {'data': '0x23b872dd000000000000000000000000ebd031016f1a4e316521e78111b99db6a3e29ffc0000000000000000000000004631018f63d5e31680fb53c11c9e1b11f1503e6f0000000000000000000000000000000000000000000002712ec5d5b7e4cd0afc',
                            'to' : CONTRACT2,
                            'from' : EOA_ADDRESS.lower()}})

        findings = provide_handle_transaction(w3)(tx_event)
        assert len(findings)==1
        