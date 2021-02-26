import sys
import os
import shutil
import random
import pandas as pd
import openpyxl as xl
import numpy as np
from copy import deepcopy
from itertools import accumulate
import itertools
import operator
import subprocess
import time
from datetime import datetime
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

if sys.version_info < (3, 6, 0):
    raise Exception("Must be using Python 3.6 or above")

try:
    from web3 import Web3
    from web3.middleware import geth_poa_middleware
except:
    print("You need to have Web3 module to use this replayer.")
    print("Go to command prompt and type in python -m pip install Web3")
    print("If error occurs during install, please see the error message and install the relevant component also")
    exit()

import json
import json_helper
import gen_input as gi
import mutate_input as mi

try:
    import eth_abi
except:
    exit()

w3 = None
NormalAccount = ""
OwnerAccount = ""
ConstructorAddressAccount = ""
AttackerContract = ""
contractmap = []
functionmap = []
failcount = 0

path_bin = r'./Dataset/Full/Smart_Contract_Binaries'
path_abi = r'./Dataset/Full/Smart_Contract_ABIs'

class Transaction:
    def __init__(self, Index, From, Function, Value, Input, Gas, Priority, Hash):
        self.Index = Index
        self.From = From
        self.Function = Function
        self.Value = Value
        self.Input = Input
        self.Gas = Gas
        self.Priority = Priority
        self.Hash = Hash

        # TODO
        self.blocks = []

    def printTx(self):
        print([self.Index, self.From, self.Function, self.Value, self.Input, self.Gas, self.Priority, self.Hash])
class Function:
    def __init__(self, Name, Input, Payable, Count):
        self.Name = Name
        self.Input = Input
        self.Payable = Payable
        self.Count = Count
        self.Seeds = []

def getAttackerAgent():
    # notdeployed = True
    # while notdeployed:
    bytecode = "606060405260006000600050556001600360006101000a81548160ff021916908302179055506000600360016101000a81548160ff02191690830217905550600060046000505560006005600050555b5b610a508061005e6000396000f3606060405236156100b6576000357c01000000000000000000000000000000000000000000000000000000009004806306661abd146101de57806315140bd1146102065780633f948cac1461023057806348cccce9146102585780635aa945a4146102705780636b66ae0e146102d45780636ed65dae14610312578063789d1c5c1461033a57806383a64c1e146103995780639e455939146104195780639eeb30e614610457578063d3e204d714610481576100b6565b6101dc5b600360009054906101000a900460ff16156101bf5760006000818150548092919060010191905055506000600360006101000a81548160ff02191690830217905550600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166002600050604051808280546001816001161561010002031660029004801561019f5780601f106101745761010080835404028352916020019161019f565b820191906000526020600020905b81548152906001019060200180831161018257829003601f168201915b50509150506000604051808303816000866161da5a03f1915050506101d9565b6001600360006101000a81548160ff021916908302179055505b5b565b005b34610002576101f06004805050610501565b6040518082815260200191505060405180910390f35b3461000257610218600480505061050a565b60405180821515815260200191505060405180910390f35b3461000257610242600480505061051d565b6040518082815260200191505060405180910390f35b61026e6004808035906020019091905050610526565b005b34610002576102d26004808035906020019091908035906020019082018035906020019191908080601f016020809104026020016040519081016040528093929190818152602001838380828437820191505050505050909091905050610591565b005b34610002576102e66004805050610706565b604051808273ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b3461000257610324600480505061072c565b6040518082815260200191505060405180910390f35b6103976004808035906020019091908035906020019082018035906020019191908080601f016020809104026020016040519081016040528093929190818152602001838380828437820191505050505050909091905050610735565b005b34610002576103ab60048050506108b1565b60405180806020018281038252838181518152602001915080519060200190808383829060006004602084601f0104600302600f01f150905090810190601f16801561040b5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b346100025761042b6004805050610952565b604051808273ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34610002576104696004805050610981565b60405180821515815260200191505060405180910390f35b34610002576104936004805050610994565b60405180806020018281038252838181518152602001915080519060200190808383829060006004602084601f0104600302600f01f150905090810190601f1680156104f35780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b60006000505481565b600360019054906101000a900460ff1681565b60056000505481565b60046000818150548092919060010191905055508073ffffffffffffffffffffffffffffffffffffffff166108fc349081150290604051809050600060405180830381858888f19350505050151561058d5760056000818150548092919060010191905055505b5b50565b6000600360016101000a81548160ff0219169083021790555081600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908302179055508060026000509080519060200190828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f1061062457805160ff1916838001178555610655565b82800160010185558215610655579182015b82811115610654578251826000505591602001919060010190610636565b5b5090506106809190610662565b8082111561067c5760008181506000905550600101610662565b5090565b50508173ffffffffffffffffffffffffffffffffffffffff1681604051808280519060200190808383829060006004602084601f0104600302600f01f150905090810190601f1680156106e75780820380516001836020036101000a031916815260200191505b509150506000604051808303816000866161da5a03f1915050505b5050565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60046000505481565b60006001600360016101000a81548160ff0219169083021790555034905082600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908302179055508160026000509080519060200190828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f106107cd57805160ff19168380011785556107fe565b828001600101855582156107fe579182015b828111156107fd5782518260005055916020019190600101906107df565b5b509050610829919061080b565b80821115610825576000818150600090555060010161080b565b5090565b50508273ffffffffffffffffffffffffffffffffffffffff168183604051808280519060200190808383829060006004602084601f0104600302600f01f150905090810190601f1680156108915780820380516001836020036101000a031916815260200191505b5091505060006040518083038185876185025a03f192505050505b505050565b60026000508054600181600116156101000203166002900480601f01602080910402602001604051908101604052809291908181526020018280546001816001161561010002031660029004801561094a5780601f1061091f5761010080835404028352916020019161094a565b820191906000526020600020905b81548152906001019060200180831161092d57829003601f168201915b505050505081565b6000600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905061097e565b90565b600360009054906101000a900460ff1681565b602060405190810160405280600081526020015060026000508054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610a415780601f10610a1657610100808354040283529160200191610a41565b820191906000526020600020905b815481529060010190602001808311610a2457829003601f168201915b50505050509050610a4d565b9056"
    abi = json.loads(
        '[{"constant":true,"inputs":[],"name":"count","outputs":[{"name":"","type":"uint256"}],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"hasValue","outputs":[{"name":"","type":"bool"}],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"sendFailedCount","outputs":[{"name":"","type":"uint256"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"contract_addr","type":"address"}],"name":"MySend","outputs":[],"payable":true,"type":"function"},{"constant":false,"inputs":[{"name":"contract_addr","type":"address"},{"name":"msg_data","type":"bytes"}],"name":"MyCallWithoutValue","outputs":[],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"call_contract_addr","outputs":[{"name":"","type":"address"}],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"sendCount","outputs":[{"name":"","type":"uint256"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"contract_addr","type":"address"},{"name":"msg_data","type":"bytes"}],"name":"MyCallWithValue","outputs":[],"payable":true,"type":"function"},{"constant":true,"inputs":[],"name":"call_msg_data","outputs":[{"name":"","type":"bytes"}],"payable":false,"type":"function"},{"constant":false,"inputs":[],"name":"getContractAddr","outputs":[{"name":"addr","type":"address"}],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"turnoff","outputs":[{"name":"","type":"bool"}],"payable":false,"type":"function"},{"constant":false,"inputs":[],"name":"getCallMsgData","outputs":[{"name":"msg_data","type":"bytes"}],"payable":false,"type":"function"},{"inputs":[],"type":"constructor"},{"payable":true,"type":"fallback"}]')
    Attackercontract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = Attackercontract.constructor().transact()
    # address = w3.toChecksumAddress("0x28ef0219735b712841d51232e853ff9a98476ff5")
    try:
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
        notdeployed = False
    except Exception as e:
        print(e)
        notdeployed = True
    return w3.eth.contract(address=tx_receipt.contractAddress,abi=abi)
    # return w3.eth.contract(address=address, abi=abi)


def reentrancyCall(input, contract):
    try:
        attacker = AttackerContract
        # transaction = w3.eth.getTransaction(tx_hash)
        ####################################### CHANGE 'MyCallWithValue' to appropriaye function in Attacker Contract
        tx_hash = attacker.functions.MyCallWithValue(contract.address, input).transact({'value': 1, 'gas': 800000})
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
        return tx_hash

        # gas = readFileForGasCost(tx_hash.hex(), 800000)
        # print('ReEntrancy Attack Gas Cost: ' + str(tx_receipt.cumulativeGasUsed))
        # print('ReEntrancy Attack Gas Cost: ' + str(gas))
    except Exception as e:
        print(e)


def initializeaccount(devmode):
    global failcount
    global w3
    global NormalAccount
    global OwnerAccount
    global AttackerContract
    global contractmap
    global functionmap
    w3 = Web3()
    try:
        print(w3.eth.blockNumber)
    except:
        failcount = failcount + 1
        if failcount < 10:
            initializeaccount(devmode)
        return
    if devmode:
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    # if you get UnhandledRequest: No providers responded to the RPC request,
    # please see https://web3py.readthedocs.io/en/stable/providers.html#choosing-provider to
    # read about how to connect to your chain

    # NORMALACCOUNT = w3.eth.accounts[1]
    # OWNERACCOUNT = w3.eth.accounts[0]
    NORMALACCOUNT = w3.toChecksumAddress("0xf97ddc7b1836c7bb14cd907ef9845a6c028428f4")
    OWNERACCOUNT = w3.toChecksumAddress("0x96780224cb07a07c1449563c5dfc8500ffa0ea2a")
    w3.eth.defaultAccount = OWNERACCOUNT
    w3.geth.personal.unlockAccount(OWNERACCOUNT, "", 20 * 60 * 60)
    w3.geth.personal.unlockAccount(NORMALACCOUNT, "123456", 20 * 60 * 60)
    # w3.parity.personal.unlockAccount(OWNERACCOUNT,"123456",20*60*60)
    # w3.parity.personal.unlockAccount(NORMALACCOUNT,"123456",20*60*60)

    ATTACKERCONTRACT = getAttackerAgent()
    # if you don't use the provided chain, please uncomment the line for normal account and owner account
    # contractmap = ReadContractAddress("/Replayer/resultinterpet/")


def getBytecode(path):
    with open(path, 'r') as f:
        return f.read().replace('\n', '')


def getABI(path):
    with open(path, 'r') as f:
        abi = f.read().replace('\n', '').replace(' ', '')
        if abi[0] == "{":
            abi = abi[7:-1]
        return abi


def genConstructorInputs(abi):
    inputs = json_helper.get_function_from_abi(abi, 'type', 'constructor', 'inputs')
    # print(inputs)
    new_input = []
    if inputs != None:
        for dict in inputs:
            new_input.append(dict['type'])
        # print(input)
        return gi.gen_input(new_input, True, ConstructorAddressAccount)
    else:
        return None


def deployContract(bytecode,abi):
    inp_seq = genConstructorInputs(abi)
    # print(inp_seq)

    contract = w3.eth.contract(abi=abi, bytecode=bytecode)

    if inp_seq is None:
        #print(contract.constructor().estimateGas())
        tx_hash = contract.constructor().transact()
    else:
        # tx_hash = contract.constructor('123', '123').transact()
        tx_hash = contract.constructor(*inp_seq).transact()
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    # print(file[:-4] + ' => ' + tx_receipt.contractAddress + ' :: Gas:' + str(tx_receipt.gasUsed))
    # print('\nCumulative Gas Used: ' + str(tx_receipt.cumulativeGasUsed) + '\n')
    return tx_receipt


def extractFunctions(funcs,abi):
    funcs_without_param = []
    funcs_with_param = []
    remove = []
    len_remove = 0
    payable = []
    non_payable = []

    for f in funcs:
        f_name = (str(f).split(' ')[1]).split('(')[0]
        # mutability = json_helper.get_function_from_abi(abi, 'name', f_name, 'stateMutability')
        # print(mutability)
        # if mutability == 'pure' or mutability == 'view':
        #     remove.append(f)
        pay = json_helper.get_function_from_abi(abi, 'name', f_name, 'payable')
        mutability = json_helper.get_function_from_abi(abi, 'name', f_name, 'constant')
        if mutability is True:
            remove.append(f)
        else:
            if (str(f).split(' ')[1]).split('(')[1] == ')>':
                funcs_without_param.append(f_name)
            else:
                funcs_with_param.append(f_name)

            if pay is True:
                payable.append(f_name)
            else:
                non_payable.append(f_name)
    len_remove = len(remove)
    for r in remove:
        funcs.remove(r)

    return [funcs,funcs_without_param,funcs_with_param,payable,non_payable]


def readGethLog(log_seek, txmap, tx_hash):
    with open('geth_run.log', 'r') as f:
        f.seek(log_seek)
        lines = f.readlines()
        log_seek = f.tell()

    for idx, line in enumerate(lines):
        if "txHash=" in line:
            tx_hash = line.split("txHash=")[1].split(" ")[0]
            if tx_hash in txmap:
                txmap[tx_hash].append(line.replace('\n', ''))
            else:
                txmap[tx_hash] = [line.replace('\n', '')]
        if '#$#' in line:
            ErrTime = lines[idx-1]
            ErrTime = datetime.strptime(
                                    '2020-' + ErrTime.split("[")[1].split("]")[0].replace('|', ' '),
                                    '%Y-%m-%d %H:%M:%S.%f')
            errors = line.split('#$#')
            errors = errors[1:]
            for e in errors:
                if e[-1] == ':':
                    e = e[:-1]
                tx_hash = e.split(":")[1].replace('\n', '')
                if tx_hash in txmap:
                    # + '&' + ErrTime
                    txmap[tx_hash].append('#$#' + e.replace('\n', '') + '&' + str(ErrTime))
                else:
                    txmap[tx_hash] = ['#$#' + e.replace('\n', '') + '&' + str(ErrTime)]
    return log_seek,txmap


def updateStorageAccessMap(txHashlist, txmap, tx_hash, RunGas, VulnerabilitiesList, ReEntrancy):

    if tx_hash in txmap:
        vulTx = []
        for line in txmap[tx_hash]:
            if '#$#' in line:
                vulnerability = line.split('&')[0]
                vulTime = line.split('&')[1]
                vulnerability = vulnerability.replace('#$#','')
                if ReEntrancy == False:
                    vul = vulnerability.split(":")[0] + ' - ' +  txHashlist[vulnerability.split(':')[1]].Function
                    VulExists = False
                    for v in VulnerabilitiesList:
                        if v.split('#')[0] == vul:
                            VulExists = True
                    if VulExists == False:
                        vulTx.append(vul + '#' +  vulTime)
                    # print('>>> >>> ' + vulnerability.split(":")[0] + txHashlist[vulnerability.split(':')[1]].From)
                else:
                    if 'Reentrancy' in vulnerability:
                        vul = vulnerability.split(":")[0] + ' - ' + txHashlist[vulnerability.split(':')[1]].Function
                        VulExists = False
                        for v in VulnerabilitiesList:
                            if v.split('#')[0] == vul:
                                VulExists = True
                        if VulExists == False:
                            VulnerabilitiesList.append(vul + '#' +  vulTime)
        for v in vulTx:
            VulnerabilitiesList.append(v)


def BB_Fuzzer(fRecord, contract, addressArray, Q, priority, Q_size, txHashlist, VulnerabilitiesList, log_seek):
    iterationCounter = 0
    Rungas = 800000

    if range(len(fRecord)) is 0:
        return [Q, Q_size, txHashlist, VulnerabilitiesList, log_seek]

    for f in fRecord:
        if len(f.Input) is not 0:
            for i in range(len(fRecord)*5):
                f.Seeds.append(gi.gen_input(f.Input, False, addressArray))

    SeqMap = {}
    TotalTx = 0

    range_seq = len(fRecord)
    for i in range(range_seq):
        try:
            size = 80

            TotalTx += size
            seq = random.choices(fRecord,k=size)
            txSeq = []
            for f in seq:
                accountsToRun = [OwnerAccount, OwnerAccount, NormalAccount]
                account = random.choice(accountsToRun)

                if f.Payable is True:
                    value = random.choice([0, 1])
                else:
                    value = 0

                if len(f.Seeds) is 0:
                    inp_seq = []
                else:
                    inp_seq = gi.gen_input(f.Input, False, addressArray)

                tx = Transaction(-999, account, f.Name, value, inp_seq, 0, priority, None)
                txSeq.append(tx)
                SeqMap[i] = txSeq
        except Exception as e:
            print(e)
    txmap = {}

    for key in SeqMap:
        for tx in SeqMap[key]:
            try:
                contract_f = contract.get_function_by_signature(tx.Function)
                if len(tx.Input) is 0:
                    tx_hash = contract_f().transact({'from': tx.From, 'value': tx.Value, 'gas': Rungas})
                else:
                    tx_hash = contract_f(*tx.Input).transact({'from': tx.From, 'value': tx.Value, 'gas': Rungas})

                tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
                tx_hash = tx_hash.hex()
                log_seek, txmap = readGethLog(log_seek, txmap, tx_hash)
                txHashlist[tx_hash] = Transaction(-999, tx.From, tx.Function, tx.Value, tx.Input, 0, tx.Priority, tx_hash)
                updateStorageAccessMap(txHashlist, txmap, tx_hash, Rungas, VulnerabilitiesList, False)
            except Exception as e:
                print(e)

    return [Q, Q_size, txHashlist, VulnerabilitiesList, log_seek, TotalTx]


def FromTransactionFindABIFunction(tx, fRecord):
    for func in fRecord:
        if tx.Function == func.Name:
            return func


def MainLoop():

    try:
        shutil.rmtree('Ethereum')
        shutil.copytree('Ethereum-backup', 'Ethereum')

        os.system('pkill -INT geth')
        if os.path.isfile('geth_run.log'):
            os.system('rm geth_run.log')
    except Exception as e:
        print('No Process to Kill')

    os.system('nohup ./geth_run.sh>>geth_run.log 2>&1 &')
    waittime = 3
    timenow = time.time()
    while True:
        if time.time() - timenow > waittime:
            break

    global w3
    global contractmap
    global NormalAccount
    global OwnerAccount
    global ConstructorAddressAccount
    global AttackerContract

    w3 = Web3()

    intermediatevariables = []
    answerreceived = False  # scriptchange
    connected = False  # scriptchange
    while not answerreceived:
        ans = 'y'  # input("Y/N?")
        if ans.lower() == "y":
            # print("Please specify the provider you are using?")
            answerreceived = True
            intermediatevariables.append(ans)
        elif ans.lower() == "n":
            print("Trying to auto connect to the ethereum chain")
            answerreceived = True
            try:
                print(
                    "Connected to chain " + w3.eth.chainId + " with latest block number:" + str(w3.eth.blockNumber))
                connected = True
                intermediatevariables.append(ans)
            except:
                print("Cannot connect to the ethereum chain")
                print("Please specify the provider you are using?")
        else:
            print("Please only answer 'Y' or 'N'")
            answerreceived = False
    answerreceived = False
    while not connected:
        # ans = input("1.HTTPProvider, 2. IPCProvider. 3. WebsocketProvider")
        ans = "1"
        if ans == "1":
            # uri = input("Please provide the endpoint uri such as 'https://localhost:8545'.")
            uri = 'http://127.0.0.1:8545'
            try:
                w3 = Web3(Web3.HTTPProvider(uri))
                print("Connected to chain with latest block number::" + str(w3.eth.blockNumber))
                connected = True
                intermediatevariables.append([ans, uri])
            except:
                print("Cannot connect to the chain. Please make sure the input provided are correct")
        elif ans == "2":
            # filesystempath = input("Please provide the file system path to the chain")
            filesystempath = '/home/imran/.ethereum/geth.ipc'
            try:
                w3 = Web3(Web3.IPCProvider(filesystempath))
                print("Connected to chain with latest block number::" + str(w3.eth.blockNumber))
                connected = True
                intermediatevariables.append([ans, filesystempath])
            except Exception as e:
                print(e)
                print("Cannot connect to the chain. Please make sure the input provided are correct")
                exit()
        elif ans == "3":
            endpointuri = input("Please provide the full URI to the RPC endpoint such as 'ws://localhost:8546'.")
            try:
                w3 = Web3(Web3.WebsocketProvider(endpointuri))
                print("Connected to chain with latest block number::" + str(w3.eth.blockNumber))
                connected = True
                intermediatevariables.append([ans, endpointuri])
            except:
                print("Cannot connect to the chain. Please make sure the input provided are correct")
        else:
            print("Please only answer 1,2,3")

    coinbase = w3.eth.coinbase
    OwnerAccount = w3.eth.accounts[0]
    NormalAccount = w3.eth.accounts[1]
    ConstructorAddressAccount = w3.eth.accounts[2]

    w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    w3.geth.personal.unlockAccount(OwnerAccount, "", 20 * 60 * 60)
    w3.geth.personal.unlockAccount(NormalAccount, "123456", 20 * 60 * 60)
    w3.geth.personal.unlockAccount(ConstructorAddressAccount, "123456", 20 * 60 * 60)

    addressArray = []

    w3.eth.defaultAccount = OwnerAccount

    count = 0
    AttackerContract = getAttackerAgent()

    write_to_excel_coverage = {}
    write_to_excel_stats = {}

    for r, d, f in os.walk(path_bin):
        for file in f:
            if '.bin' in file:
                count = count + 1

                try:
                    print('\nContract # ' + str(count) + ' - ' + file[:-4])
                    Time_start = time.time()
                    bytecode = getBytecode(path_bin + '/' + file)
                    abi = getABI(path_abi + '/' + file[:-4] + '.abi')

                    ### Deployment of Contract
                    tx_receipt = deployContract(bytecode, abi)

                    contract = w3.eth.contract(address=tx_receipt.contractAddress, abi=abi)
                    byte_code = w3.eth.getCode(contract.address)
                    funcs = contract.all_functions()

                    ### Extract Functions
                    [funcs, funcs_without_param, funcs_with_param, payable, non_payable] = extractFunctions(funcs, abi)
                    fRecord = []

                    for f in funcs:
                        f_name = str(f).split(' ')[1].split('>')[0]
                        inp = str(f).split(' ')[1].split('(')[1]
                        if inp != ')>':
                            inputs = inp[:-2].split(',')
                        else:
                            inputs = []
                        if f_name in payable:
                            pay = True
                        else:
                            pay = False
                        fun = Function(f_name, inputs, pay, 0)
                        fRecord.append(fun)

                    if len(fRecord) == 0:
                        print('No Functions to fuzz')
                        continue

                    Q = []
                    Q_size = 0
                    priority = 100
                    txHashlist = {}
                    VulnerabilitiesList = []
                    log_seek = 0
                    Totaltx = 0

                    [Q, Q_size, txHashlist, VulnerabilitiesList, log_seek, Totaltx] =\
                        BB_Fuzzer(fRecord, contract, addressArray, Q, priority, Q_size,txHashlist, VulnerabilitiesList, log_seek)

                    starttime = None
                    with open('geth_run.log', 'r') as f:
                        lines = f.readlines()
                        for line in lines:
                            if 'Submitted contract creation' in line:
                                starttime = datetime.strptime(
                                    '2020-' + line.split("[")[1].split("]")[0].replace('|', ' '),'%Y-%m-%d %H:%M:%S.%f')
                    vulTimeList = []
                    for vul in VulnerabilitiesList:
                        vulTime = vul.split('#')[1]
                        vulTime = datetime.strptime(vulTime,'%Y-%m-%d %H:%M:%S.%f')
                        vulTime = vulTime - starttime
                        vulTimeList.append(vulTime.seconds + vulTime.microseconds / 1000000)

                    time_spent = round(time.time() - Time_start, 3)
                    Result = [len(fRecord), Totaltx, time_spent,
                              len(VulnerabilitiesList), VulnerabilitiesList, vulTimeList]
                    print(str(Result)[1:-1])

                    shutil.copy('geth_run.log', str(count) + '-' + file[:-4] + '.log')
                    shutil.move(str(count) + '-' + file[:-4] + '.log', 'logs')
                    open('geth_run.log', 'w').close()

                    write_to_excel_stats[file[:-4]] = Result

                    DataWriter = pd.ExcelWriter('Results (W,A,D).xlsx')
                    DataToWrite2 = pd.DataFrame.from_dict(write_to_excel_stats, orient='index')
                    DataToWrite2.columns = ['SAFs', 'TotalTx', 'TimeSpent', 'Count(Vul)', 'Vul', 'VulTime']
                    DataToWrite2.to_excel(DataWriter, sheet_name='Sheet1')
                    DataWriter.save()

                except Exception as e:
                    print(e)
                    shutil.copy('geth_run.log', str(count) + '-' + file[:-4] + '.log')
                    open('geth_run.log', 'w').close()
    print(count)

    shutil.rmtree('Ethereum')
    shutil.copytree('Ethereum-backup', 'Ethereum')

    os.system('pkill -INT geth')
    os.system('rm geth_run.log')


if __name__ == '__main__':
    MainLoop()
