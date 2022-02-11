EOA_ADDRESS = '0x1FCdb04d0C5364FBd92C73cA8AF9BAA72c269107'
EOA_ADDRESS2 = '0x1FCdb04d0C5364FBd92C73cA8AF9BAA72c269108'
CONTRACT_ADDRESS = '0x04c90C198b2eFF55716079bc06d7CCc4aa4d7512'

class Web3Mock:
    def __init__(self):
        self.eth = EthMock()


class EthMock:
    def __init__(self):
        self.contract = ContractMock()

    def get_code(self, address):
        if address==CONTRACT_ADDRESS:
            return b"363d3d373d3d3d363d736523ac15ec152cb70a334230f6c5d62c5bd963f15af43d82803e903d91602b57fd5bf3"
        elif address==EOA_ADDRESS:
            return b""
        elif address==EOA_ADDRESS2:
            return b""
        else:
            return b""

class ContractMock:
    def __init__(self):
        self.functions = FunctionsMock()

    def __call__(self, address, *args, **kwargs):
        return self


class FunctionsMock:
    def __init__(self):
        self.return_value = None

    def call(self, *_, **__):
        return self.return_value
