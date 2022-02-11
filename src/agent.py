from datetime import datetime, timedelta
import forta_agent
from forta_agent import get_json_rpc_url
from web3 import Web3
from src.findings import PhishingFindings
from src.constants import TRANSFER_FROM_TO, TRANSFER_FROM_ABI, TOP_TRANSACTOR_LIMIT, APPROVE_FUNCTION_ABI, APPROVE_SPENDER, APPROVE_VALUE, INCREASE_ALLOWANCE_ABI,\
    INCREASE_ALLOWANCE_ADDEDVALUE, INCREASE_ALLOWANCE_SPENDER, APPROVAL_CONTRACT_COUNT_THRESHOLD,TRIGGER_PERIOD_DAYS,EOA_TRANSACTION_COUNT_FILTER,\
    TRANSFER_FROM_VALUE, TRANSFER_FROM_FROM


web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

EOA_APPROVAL_COUNTS = {}
EOA_APPROVAL_LAST_ALERTED = {}
EOA_TRANSACTION_COUNTS = {}
EOA_TRANSFER_LAST_ALERTED = {}

def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    global EOA_APPROVAL_COUNTS
    EOA_APPROVAL_COUNTS = {}
    global EOA_APPROVAL_LAST_ALERTED
    EOA_APPROVAL_LAST_ALERTED = {}
    global EOA_TRANSACTION_COUNTS
    EOA_TRANSACTION_COUNTS = {}
    global EOA_TRANSFER_LAST_ALERTED
    EOA_TRANSFER_LAST_ALERTED = {}

def is_contract(w3, address) -> bool:
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = w3.eth.get_code(Web3.toChecksumAddress(address))
    return code!=b''

def maintain_top_eoa_transactors(w3, from_):
    """
    this function counts transactions for EOAs, but only keesp top TOP_TRANSACTOR_LIMIT entries 
    to not bloat memory
    :param from_: forta_agent.transaction_event.from_
    """
    if not is_contract(w3, from_):
        if EOA_APPROVAL_COUNTS.get(from_) is None:
            EOA_TRANSACTION_COUNTS[from_]=1

        EOA_TRANSACTION_COUNTS[from_]+=1

        if len(EOA_APPROVAL_COUNTS)>TOP_TRANSACTOR_LIMIT:
            del EOA_TRANSACTION_COUNTS[min(EOA_TRANSACTION_COUNTS, key=EOA_TRANSACTION_COUNTS.get)]

def detect_suspicious_erc20_eoa_approvals(transaction_event:forta_agent.transaction_event.TransactionEvent, w3) -> list:
    """
    this function detects whether an EOA was granted approval to multiple ERC-20 contracts
    :param transaction_event: forta_agent.transaction_event.TransactionEvent
    :param w3: web3 object, it was added here to be able to insert web3 mock and test the function
    :return: findings: list
    """
    global EOA_APPROVAL_COUNTS
    global EOA_APPROVAL_LAST_ALERTED
    global EOA_TRANSACTION_COUNTS
    findings = []

    if transaction_event.receipt.status==0:
        return findings

    from_lower = transaction_event.from_.lower()
    maintain_top_eoa_transactors(w3, from_lower)

    approvals = transaction_event.filter_function(APPROVE_FUNCTION_ABI)
    increase_allowance = transaction_event.filter_function(INCREASE_ALLOWANCE_ABI)

    for event in approvals+increase_allowance:
        granted_amount = event[1][INCREASE_ALLOWANCE_ADDEDVALUE] if event[1].get(INCREASE_ALLOWANCE_ADDEDVALUE) is not None else event[1][APPROVE_VALUE]
        if granted_amount==0:
            return findings

        granted_to = event[1][INCREASE_ALLOWANCE_SPENDER] if event[1].get(INCREASE_ALLOWANCE_SPENDER) is not None else event[1][APPROVE_SPENDER]
        granted_to_lower = granted_to.lower()
        if is_contract(w3, granted_to_lower):
            return findings

        if granted_to_lower == from_lower:
            return findings

        if EOA_APPROVAL_COUNTS.get(granted_to_lower) is None:
            EOA_APPROVAL_COUNTS[granted_to_lower] = set()
            EOA_TRANSACTION_COUNTS[granted_to_lower] = 1
        EOA_APPROVAL_COUNTS[granted_to_lower].add(transaction_event.to)

        uniq_approval_contract_count = len(EOA_APPROVAL_COUNTS[granted_to_lower])
        if uniq_approval_contract_count>=APPROVAL_CONTRACT_COUNT_THRESHOLD\
            and EOA_TRANSACTION_COUNTS[granted_to_lower]<=EOA_TRANSACTION_COUNT_FILTER:

            last_contract = transaction_event.to.lower()
            last_victim = transaction_event.from_.lower()
            last_tx_hash = transaction_event.receipt.transaction_hash
            alert_time = datetime.fromtimestamp(transaction_event.block.timestamp)

            if EOA_APPROVAL_LAST_ALERTED.get(granted_to_lower) is None:
                EOA_APPROVAL_LAST_ALERTED[granted_to_lower] = (uniq_approval_contract_count, alert_time)
                findings.append(PhishingFindings.suspicious_erc20_eoa_approvals(granted_to_lower,
                                                                                    last_contract,
                                                                                    last_victim,
                                                                                    last_tx_hash,
                                                                                    uniq_approval_contract_count))

            print(EOA_APPROVAL_LAST_ALERTED[granted_to_lower][1]-alert_time)
            if uniq_approval_contract_count>EOA_APPROVAL_LAST_ALERTED[granted_to_lower][0] \
                and (alert_time-EOA_APPROVAL_LAST_ALERTED[granted_to_lower][1])>timedelta(days=TRIGGER_PERIOD_DAYS):
                EOA_APPROVAL_LAST_ALERTED[granted_to_lower] = (uniq_approval_contract_count, alert_time)
                findings.append(PhishingFindings.suspicious_erc20_eoa_approvals(granted_to_lower,
                                                                                    last_contract,
                                                                                    last_victim,
                                                                                    last_tx_hash,
                                                                                    uniq_approval_contract_count))

    return findings

def detect_exploit_erc20_eoa_transfers(transaction_event: forta_agent.transaction_event.TransactionEvent, w3) -> list:
    """
    this function detects whether an EOA that was identified as detect_suspicious_erc20_eoa_approvals now proceeds to issue transferFrom transactions
    :param transaction_event: forta_agent.transaction_event.TransactionEvent
    :param w3: web3 object, it was added here to be able to insert web3 mock and test the function
    :return: findings: list
    """
    global EOA_TRANSFER_LAST_ALERTED
    global EOA_TRANSACTION_COUNTS
    global EOA_APPROVAL_COUNTS

    findings = []

    if transaction_event.receipt.status==0:
        return findings

    transfer_from = transaction_event.filter_function(TRANSFER_FROM_ABI)
    for event in transfer_from:
        # initiator is not a contract
        from_lower = transaction_event.from_.lower()
        if is_contract(w3, from_lower):
            return findings

        granted_amount = event[1][TRANSFER_FROM_VALUE]
        if granted_amount==0:
            return findings

        if EOA_TRANSACTION_COUNTS[from_lower]>EOA_TRANSACTION_COUNT_FILTER:
            return findings

        to_lower = transaction_event.to.lower()
        if EOA_APPROVAL_COUNTS.get(from_lower) is not None\
            and to_lower in EOA_APPROVAL_COUNTS[from_lower]\
            and len(EOA_APPROVAL_COUNTS[from_lower])>=APPROVAL_CONTRACT_COUNT_THRESHOLD:

            alert_time = datetime.fromtimestamp(transaction_event.block.timestamp)

            if EOA_TRANSFER_LAST_ALERTED.get(from_lower) is None:
                EOA_TRANSFER_LAST_ALERTED[from_lower] = alert_time
                findings.append(PhishingFindings.exploit_erc20_eoa_transfers(from_lower,
                                                                        to_lower,
                                                                        event[1][TRANSFER_FROM_TO].lower(),
                                                                        event[1][TRANSFER_FROM_FROM].lower(),
                                                                        transaction_event.receipt.transaction_hash))

            if (alert_time-EOA_TRANSFER_LAST_ALERTED[from_lower])>timedelta(days=TRIGGER_PERIOD_DAYS):
                EOA_TRANSFER_LAST_ALERTED[from_lower] = alert_time
                findings.append(PhishingFindings.exploit_erc20_eoa_transfers(from_lower,
                                                                        to_lower,
                                                                        event[1][TRANSFER_FROM_TO].lower(),
                                                                        event[1][TRANSFER_FROM_FROM].lower(),
                                                                        transaction_event.receipt.transaction_hash))
    return findings

def provide_handle_transaction(w3):
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return detect_suspicious_erc20_eoa_approvals(transaction_event, w3)+detect_exploit_erc20_eoa_transfers(transaction_event, w3)

    return handle_transaction

real_handle_transaction = provide_handle_transaction(web3)

def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    return real_handle_transaction(transaction_event)