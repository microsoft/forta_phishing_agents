from forta_agent import Finding, FindingType, FindingSeverity

class PhishingFindings:
    @staticmethod
    def suspicious_erc20_eoa_approvals(to_address: str, last_contract: str, last_victim: str, last_tx_hash: str, 
                                             uniq_approval_contract_count: int) -> Finding:
        return Finding({
            'name': 'Suspicious ERC-20 EOA Approvals',
            'description': f'{to_address} was granted approvals to {uniq_approval_contract_count} ERC-20 contracts',
            'alert_id': 'PHISHING-SUS-ERC20-EOA-APPROVALS',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.High,
            'metadata': {
                'last_contract': last_contract,
                'last_tx_hash': last_tx_hash,
                'last_victim': last_victim,
                'uniq_approval_contract_count': uniq_approval_contract_count
            }
        })

    @staticmethod
    def exploit_erc20_eoa_transfers(from_address: str, contract: str, attacker: str, victim: str, tx_hash: str) -> Finding:
        return Finding({
            'name': 'ERC-20 Transfer by Suspicious Account',
            'description': f'{from_address} transferred funds from {contract} contract to address {attacker}',
            'alert_id': 'PHISHING-SUS-ERC20-EOA-TRANSFERS',
            'type': FindingType.Exploit,
            'severity': FindingSeverity.Critical,
            'metadata': {
                'last_contract': contract,
                'last_attacker_address': attacker,
                'last_tx_hash': tx_hash,
                'last_victim': victim
            }
        })
