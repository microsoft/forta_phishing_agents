# **Phishing Exploit Agent**

1. **Evidence of Phishing**
   
          Users approving token transfers to an externally owned address (EOA) may be a behavior indicative of a phishing attack.
          
          This challenge is to create an agent that will detect when a high number (e.g. 10 or more) of EOAs call the approve() or increaseAllowance() methods for the same target EOA over an extend period of time (e.g. 6 hours ~ 1600 blocks). The finding should include the affected addresses, the alleged attacker's address, and the addresses and amounts of tokens involved. Be certain to filter out smart contracts (i.e. approve() called by a smart contract or a smart contract that is the designated spender for an approve() call) and EOAs for any centralized exchanges (e.g. FTX exchange: 0x2FAF487A4414Fe77e2327F0bf4AE2a264a776AD2).
          
          The agent should trigger when run against the following block range: 13650638 to 13652198
          
          - ERC20 Reference
            - [`approve()`](https://docs.openzeppelin.com/contracts/4.x/api/token/erc20#IERC20-approve-address-uint256-)
            - [`increaseAllowance()`](https://docs.openzeppelin.com/contracts/4.x/api/token/erc20#ERC20-increaseAllowance-address-uint256-)
          - Example phishing attacks
            -[BadgerDAO](https://rekt.news/badger-rekt/)

   **Detection Logic**

    In the BaderDAO Hack, first, the attacker modified the BadgerDAO frontend to trick unsuspected users - over a period of almost 2 weeks - in granting ERC-20 approvals to the attacker account (0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107) (e.g. https://etherscan.io/tx/0x68fe0d144cd08a0592b818486101bb803a42c6378419f2198665f136065c1283 and https://etherscan.io/tx/0x1a36556f7b18604c01cd76765f8d88e6a47188647a350c526f5161ed2f8c990f). This attacker account was an EOA that was granted approvals to a broad range of ERC-20 contracts. This is highly unusual as granting approvals is usually done to contracts (e.g. DEXes) or EOA transactions have 1:* relationship with ERC-20 contract and approved EOA (e.g. contract 0x4527a3b4a8a150403090a99b87effc96f2195047). There are some legitimate EOAs (e.g. FTX Ex 0x2faf487a4414fe77e2327f0bf4ae2a264a776ad2) that differ from the attacker account in the high transaction volume. 

   ![flow_chart.png](https://github.com/cseifert1/forta_contest_4/blob/master/docs/flow_chart.png?raw=true)

    As such, the detection logic of the agent is a simple heuristic looking for successful grant (approval amount > 0) approvals (approve and increadeAllowance calls) to an EOA if that EOA does not have a high transaction volume associated with it. This alert will only trigger once per EOA per defined period if approval volume has increased.

    Second, on 12/2/2021, the attacker (0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107) transferred funds from various ERC-20 contracts to attacker controlled EOAs (see block 13726863-1365791 of https://etherscan.io/address/0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107):
    
        - 0x91d65d67fc573605bcb0b5e39f9ef6e18afa1586
        - 0xecd91d07b1b6b81d24f2a469de8e47e3fe3050fd
        - 0x4fbf7701b3078b5bed6f3e64df3ae09650ee7de5
        - 0x0b88a083dc7b8ac2a84eba02e4acb2e5f2d3063c
        - 0xa33b95ea28542ada32117b60e4f5b4cb7d1fc19b
        - 0x1b1b391d1026a4e3fb7f082ede068b25358a61f2
        - 0x2ef1b70f195fd0432f9c36fb2ef7c99629b0398c
        - 0xe06ed65924db2e7b4c83e07079a424c8a36701e5
        - 0x691da2826ac32bbf2a4b5d6f2a07ce07552a9a8e
        - 0xbbfd8041ebde22a7f3e19600b4bab4925cc97f7d

    Detection logic of the agent will trigger on previously incriminated EOA invoking transfers from ERC-20 contracts.   

    *Future work*
    - cluster EOAs into related accounts to identified more distributed approval attempts
    - incorporate time series anomaly detection to identify unusual signals based on volume (note, BadgerDAO was not unusual volume as approvals were initiated by users as part of normal traffic)
    

   **Alerts**
    - `PHISHING-SUS-ERC20-EOA-APPROVALS`
        - Alert when an EOA address was granted approvals to multiple ERC-20 contracts; only fires once in 7 day period and if ERC-20 contract approval count has increased. Since multiple approvals are used to trigger, but metadata only contains detailed information of last approval, it's advisable to review all approvals for the EOA address.
        Note, since some exchanges operate with EOAs, it is possible that FPs are raised from those EOAs. Provisions are made to filter out those EOAs in the agent. 
        - Severity always set to `High`
        - FindingType always set to `Suspicious`
        - Metadata:
            - `last_contract` - Address of the last contract that was approval granted to.
            - `last_tx_hash` - Transaction hash of last approval.
            - `last_victim` - Address of the last victim that granted approval.
            - `uniq_approval_contract_count` - unique count of all ERC 20 contracts for which approvals were made.


    - `PHISHING-SUS-ERC20-EOA-TRANSFERS`
        - Alert when an suspicious EOA addresses (identified through `PHISHING-SUS-ERC20-EOA-APPROVALS`) proceed to drain funds by issuing transfer from transaction to smart contract. Since multiple transfer froms will likely be observed, but metadata only contains detailed information of last transfer from, it's advisable to review all transfer from actions for the attacker address.
        Note, since some exchanges operate with EOAs, it is possible that FPs are raised from those EOAs. Provisions are made to filter out those EOAs in the agent. 
        - Severity always set to `Critical`
        - FindingType always set to `Exploit`
        - Metadata:
            - `last_contract` - Address of the last contract on which funds were transferred.
            - `last_tx_hash` - Transaction hash of last transfer from tx.
            - `last_victim` - Address of the last victim for which funds were transferred.
            - `last_attacker_address` - Address of last attacker address to which funds were transferred to.

   **Supported Chains**

    - Ethereum

   **Requirements**

    - Python 3.10

   **Tests**

    Run 'npm test' for unit test. 
    
    Executing agent against BaderDAO Hack blocks: 13650638 to 13652198 results in the following alerts:
    ```
    1 findings for transaction 0xaf5ce541959519cfa3ae6314e3c05109f730039c9e7fbcccd2cd4ac2e660105d {
    "name": "Suspicious ERC-20 EOA Approvals",
    "description": "0x2faf487a4414fe77e2327f0bf4ae2a264a776ad2 was granted approvals to 2 ERC-20 contracts",
    "alertId": "PHISHING-SUS-ERC20-EOA-APPROVALS",
    "protocol": "ethereum",
    "severity": "High",
    "type": "Suspicious",
    "metadata": {
      "last_contract": "0x42bbfa2e77757c645eeaad1655e0911a7553efbc",
      "last_tx_hash": "0xaf5ce541959519cfa3ae6314e3c05109f730039c9e7fbcccd2cd4ac2e660105d",
      "last_victim": "0x41620efea2b23d7f1225203fe4f7b19e3e5739ac",
      "uniq_approval_contract_count": 2
    }
    ```

    ```
    1 findings for transaction 0xccc9ea1cbe146e274aff202722307b1443b781af67363bf2f256e0cc39cc1d0a {
      "name": "ERC-20 Transfer by Suspicious Account",
      "description": "0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107 transferred funds from 0x6def55d2e18486b9ddfaa075bc4e4ee0b28c1545 contract to address 0x91d65d67fc573605bcb0b5e39f9ef6e18afa1586",
      "alertId": "PHISHING-SUS-ERC20-EOA-TRANSFERS",
      "protocol": "ethereum",
      "severity": "Critical",
      "type": "Exploit",
      "metadata": {
        "last_contract": "0x6def55d2e18486b9ddfaa075bc4e4ee0b28c1545",
        "last_attacker_address": "0x91d65D67FC573605bCb0b5E39F9ef6E18aFA1586",
        "last_tx_hash": "0xccc9ea1cbe146e274aff202722307b1443b781af67363bf2f256e0cc39cc1d0a",
        "last_victim": "0x38b8F6af1D55CAa0676F1cbB33b344d8122535C2"
      }
    }
    ```

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
