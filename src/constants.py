APPROVE_FUNCTION_ABI = '{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_value","type":"uint256"}],"name":"approve",\
    "outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"}'   
INCREASE_ALLOWANCE_ABI = '{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"addedValue",\
    "type":"uint256"}],"name":"increaseAllowance","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable",\
    "type":"function"}'
TRANSFER_FROM_ABI = '{"name":"transferFrom","type":"function","constant":false,"inputs":[{"name":"from","type":"address"},{"name":"to","type":\
    "address"},{"name":"value","type":"uint256"}],"outputs":[],"payable":false,"stateMutability":"nonpayable"}'

APPROVE_SPENDER = "_spender"
APPROVE_VALUE = "_value"
INCREASE_ALLOWANCE_SPENDER = "spender"
INCREASE_ALLOWANCE_ADDEDVALUE = "addedValue"

APPROVAL_CONTRACT_COUNT_THRESHOLD = 2
TRIGGER_PERIOD_DAYS = 7 #only trigger each alert type once in 7 days; in case of approval, only if approval count has increased
EOA_TRANSACTION_COUNT_FILTER = 250 #filter out EOAs (e.g. FTX) that show high transaction volume

TRANSFER_FROM_VALUE = "value"
TRANSFER_FROM_FROM = "from"
TRANSFER_FROM_TO = "to"

TOP_TRANSACTOR_LIMIT = 1000