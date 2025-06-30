# %%
from qiskit import *
import math
import numpy as np
import hashlib
from qiskit.tools.visualization import circuit_drawer
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import Padding
import random
import time
import json

# %%
simulator = Aer.get_backend('qasm_simulator')

# %% [markdown]
# Parameter Definition 

# %%
# delta parameter
delta = 1/8

# length of secret
m = 2

# length of hash
k = 2

n = m + k

N = math.ceil(4*n*(1+delta))

# error rate
error_rate = 0.5

# path to database
sm_cc_db = "./db/sm_cc.txt"
sm_nan_db = "./db/sm_nan.txt"
nan_cc_db = "./db/nan_cc.txt"

# length of challenge

len_of_R = 2**4

# printing

print(f'{delta=}')
print(f'{m=}')
print(f'{k=}')
print(f'{n=}')
print(f'{N=}')

# %% [markdown]
# File handling

# %%
def addSMToCC(sm, secret_key):
    '''
    sm(string): name of smart meter
    key(string): binary string of secret_key
    return-
    bool: True or False if file saving was successfull
    '''
    with open(sm_cc_db, "a") as file:
        file.write(f'{sm}:{secret_key}\n')
    return True

# %%
def addSMToNAN(sm, session_key):
    '''
    sm(string): name of smart meter
    key(string): binary string of session_key
    return-
    bool: True or False if file saving was successfull
    '''
    with open(sm_nan_db, "a") as file:
        file.write(f'{sm}:{session_key}:{0}\n')
    return True

# %%
def addNANToCC(nan, secret_key):
    '''
    nan(string): name of NAN Gateway
    key(string): binary string of secret key
    return-
    bool: True or False if file saving was successfull
    '''
    with open(nan_cc_db, "a") as file:
        file.write(f'{nan}:{secret_key}\n')
    return True

# %%
def getSMFromCC(sm):
    '''
    sm(string): name of smart meter
    return-
    key(string): binary string of secret key
    '''
    with open(sm_cc_db, "r") as file:
        for row in file.read().split('\n')[:-1]:
            [_sm, _key] = row.split(':')
            if _sm == sm:
                return _key
    return None

# %%
def getSMFromNAN(sm):
    '''
    sm(string): name of smart meter
    return-
    key(string): binary string of session key
    '''
    with open(sm_nan_db, "r") as file:
        for row in file.read().split('\n')[:-1]:
            [_sm, _key, _md] = row.split(':')
            if _sm == sm:
                return _key, _md
    return None

# %%
def getNANFromCC(nan):
    '''
    nan(string): name of NAN Gateway
    return-
    key(string): binary string of secret key
    '''
    with open(nan_cc_db, "r") as file:
        for row in file.read().split('\n')[:-1]:
            [_nan, _key] = row.split(':')
            if _nan == nan:
                return _key
    return None

# %% [markdown]
# SQDSC

# %% [markdown]
# State
# $$(0, 1, 2, 3) = (|0>, |1>, |+>, |->)$$

# %%
def encodeQubits(state, circuit, idx):
    """
    state (int): (0, 1, 2, 3) = (|0>, |1>, |+>, |->)
    circuit (QuantumCircuit): the circuit used for communication
    idx (int): index of the qubit
    """
    if state%2:
        circuit.x(idx)
    if state >= 2:
        circuit.h(idx)
    return circuit

# %%
def sqdsc(key):
    """
    key(string): binary string of key
    return-
    bool: True or False if protocol was successfull
    """

    # Step 1
    
    # generate random states of A batch
    A = np.random.randint(4, size=N)

    print("States: (0, 1, 2, 3) = (|0>, |1>, |+>, |->)")
    print("A: ", end="")
    print(A)
    
    # circuit for communication
    circuit = QuantumCircuit(N, N)
    
    for idx, elem in enumerate(A):
        circuit = encodeQubits(elem, circuit, idx)
    
    # Step 2
    
    # S batch
    
    S = np.random.choice(N, N//2, replace=False)
    S.sort()
    
    print("S: ", end="")
    print(S)

    # T batch
    
    T = []
    
    for i in range(N):
        if i not in S:
            T.append(i)
    
    T = np.array(T)
    
    print("T: ", end="")
    print(T)

    # sm decesion to measure S
    toMeasureS = np.random.randint(2, size=N//2)
    
    tempS = dict(zip(S, toMeasureS))
    
    print("(S[i], toMeasureS[i])", end="")
    print(tempS)

    # measurement of qubits in S by sm

    sec_tested = 0

    for i, d in tempS.items():
        sec_tested  += d
        if d:
            circuit.measure(i, i)


    # storing results by sm

    result_sm = execute(circuit, backend=simulator, shots=1).result()
    count_sm_dict = result_sm.get_counts(circuit)
    count_sm = list(count_sm_dict.keys())[0][::-1]


    ### TAMPERING
    
    circuit.barrier()
    
    # measurement of qubits in S by nan

    tempS = dict(zip(S, toMeasureS))

    for i, d in tempS.items():
        if d:
            circuit.measure(i, i)
    
    # storing results by sm

    result_nan = execute(circuit, backend=simulator, shots=1).result()
    count_nan_dict = result_nan.get_counts(circuit)
    count_nan = list(count_nan_dict.keys())[0][::-1]

    # error checking

    e = 0

    for i in toMeasureS:
        e += int((count_sm[i] != count_nan[i]))

    e = e/sec_tested

    if e >= error_rate:
        print("Line 85: Error rate is higher than threshold. Protocol Aborted")
        return False
    
    # step 3

    circuit.barrier()

    # generating B batch

    B = []

    for t in T:
        if A[t] <= 1:
            B.append(t)
    
    if len(B) < n:
        print("Line 103: len(B) < m. Protocol Aborted")
        return False

    B = np.random.choice(np.array(B), n, replace=False)
    B.sort()

    print("B: ", end="")
    print(B)

    # message and hash generation

    M = key

    print("M: ", end="")
    print(M)

    H_of_M = bin(int(hashlib.sha512(M.encode('utf-8')).hexdigest(), 16))[2:2+k]

    print("H_of_M: ", end="")
    print(H_of_M)

    M_hat = M + H_of_M

    # encoding in quantum circuit

    for idx, b in enumerate(B):
        if M_hat[idx] == "1":
                circuit.x(b)

    # measurement by nan
    
    circuit.barrier()

    for b in B:
        circuit.measure(b, b)

    result_final = execute(circuit, backend=simulator, shots=1).result()
    count_final_dict = result_final.get_counts(circuit)
    count_final = list(count_final_dict.keys())[0][::-1]

    # calculating M_prime_hat

    M_prime_hat = ""
    for b in B:
        if int(count_final[b]) == A[b]:
            M_prime_hat += "0"
        else:
            M_prime_hat += "1"

    M_prime = M_prime_hat[:m]
    h_prime = M_prime_hat[m:m+k]

    print("M_prime: ", end="")
    print(M_prime)

    print("h_prime: ", end="")
    print(h_prime)

    H_of_M_prime = bin(int(hashlib.sha512(M_prime.encode('utf-8')).hexdigest(), 16))[2:2+k]

    if H_of_M_prime != h_prime:
        print("Line 147: Hashes dont match. Protocol Aborted")
        return False

    return True

# %% [markdown]
# # Phase 1

# %%
def phase1(sm, nan, sm_key, nan_key):
    """
    sm(string): name of smart meter
    nan(string): name of NAN Gateway
    sm_key(string): binary string of secret key for smart meter
    nan_key(string): binary string of secret key for NAN gateway
    return-
    bool: True or False if phase 1 was successfull
    """

    if sqdsc(sm_key) and sqdsc(nan_key):
        if addSMToCC(sm, sm_key) and addNANToCC(nan, sm_key):
            return True
    return False

# %% [markdown]
# # Phase 2

# %%
def getChallenge():
    return f'{random.getrandbits(len_of_R):=016b}'

# %%
def phase2(sm, sm_key):
    """
    sm(string): name of sm
    sm_key(string): binary string of secret key
    return-
    bool: True or False if phase 2 was successfull
    """

    # SM initiates connection with CC via NAN

    # CC generates Rb and sends it to SM via NAN

    Rb = getChallenge()
    print(f'{Rb=}')
    
    # SM generates their own challenge string

    Ra = getChallenge()
    print(f'{Ra=}')

    # encrypted package by SM and sent to CC via NAN

    while len(sm_key) < 16:
            sm_key = "0" + sm_key

    cipher = AES.new((sm_key).encode('utf-8'), AES.MODE_ECB)

    padded_data = Padding.appendPadding(
        Ra+Rb, blocksize=Padding.AES_blocksize, mode=0)
    
    sm_package = cipher.encrypt(padded_data.encode("utf-8"))

    # CC decrypts and checks if the data matches

    cc_sm_key = getSMFromCC(sm)

    while len(cc_sm_key) < 16:
            cc_sm_key = "0" + cc_sm_key

    print(f'{cc_sm_key=}')

    cipher = AES.new((cc_sm_key).encode('utf-8'), AES.MODE_ECB)

    decrypted_data = Padding.removePadding(
    cipher.decrypt(sm_package).decode(), mode=0)
    
    _Rb = decrypted_data[16:]
    _Ra = decrypted_data[:16]

    print(f'{_Ra=}')
    print(f'{_Rb=}')

    if Rb != _Rb:
        return False

    # CC sends SM its own package via NAN

    cipher = AES.new((sm_key).encode('utf-8'), AES.MODE_ECB)

    padded_data = Padding.appendPadding(
        _Ra+_Rb, blocksize=Padding.AES_blocksize, mode=0)
    
    cc_package = cipher.encrypt(padded_data.encode("utf-8"))

    # SM decrypts and checks if the data matches

    cipher = AES.new((sm_key).encode('utf-8'), AES.MODE_ECB)

    decrypted_data = Padding.removePadding(
    cipher.decrypt(cc_package).decode(), mode=0)
    
    __Rb = decrypted_data[16:]
    __Ra = decrypted_data[:16]

    print(f'{__Ra=}')
    print(f'{__Rb=}')

    if Ra != __Ra or Rb != __Rb:
        return False

    return True

# %% [markdown]
# # Phase 3

# %%
def phase3(sm, sm_key):
    """
    sm(string): name of smart meter
    sm_key(string): binary string of session key for smart meter
    return-
    bool: True or False if phase 1 was successfull
    """

    if sqdsc(sm_key):
        if addSMToNAN(sm, sm_key):
            return True
    return False

# %% [markdown]
# # Phase 4

# %%
def getBillReq(session_key, PSID, MDCurr):
    '''
    session_key(str): SessionKey of SM
    PSID(str): PSID of SM
    MDCurr(float): current metering data
    '''


    while len(session_key) < 16:
            session_key = "0" + session_key

    Tsm = time.time()

    message = {
        "MDCurr": MDCurr,
        "PSID": PSID,
        "Tsm": Tsm,
    }

    cipher = AES.new((session_key).encode('utf-8'), AES.MODE_ECB)

    padded_data = Padding.appendPadding(
        json.dumps(message), blocksize=Padding.AES_blocksize, mode=0)
    
    package = cipher.encrypt(padded_data.encode("utf-8"))
    

    
    return {
        "package": package,
        "PSID": PSID,
    }

# %%
def updateMD(PSID, MD):
    '''
    PSID(str): PSID of SM
    '''

    data = []

    with open(sm_nan_db, "r") as file:
        for row in file.read().split('\n')[:-1]:
            [_PSID, _SharedKey, _md] = row.split(':')
            if _PSID == PSID:
                _md = str(MD)
                row = ":".join([_PSID, _SharedKey, _md])
            data.append(row)
    
    with open(sm_nan_db, "w") as file:
        for row in data:
            file.write(f'{row}\n')
    return True

# %%
def phase4(session_key, PSID, MDCurr):
    '''
    session_key(str): SessionKey of SM
    PSID(str): PSID of SM
    MDCurr(float): current metering data
    '''
    print(f'{PSID=}')

    BillReq = getBillReq(session_key, PSID, MDCurr)

    package = BillReq["package"]

    print(f'{session_key=}')
    [nan_session_key, MDPrev] = getSMFromNAN(PSID)
    print(f'{nan_session_key=}')

    while len(nan_session_key) < 16:
        nan_session_key = "0" + nan_session_key

    cipher = AES.new((nan_session_key).encode('utf-8'), AES.MODE_ECB)

    decrypted_data = Padding.removePadding(
        cipher.decrypt(package).decode(), mode=0)

    print(f'{decrypted_data=}')

    data_obj = json.loads(decrypted_data)

    print(f'{data_obj=}')

    if time.time() - float(data_obj["Tsm"]) > 40*1000:
        print("Old request")
        return False

    if data_obj["PSID"] != PSID:
        print("Invalid data")
        return False

    if updateMD(PSID, MDCurr - int(MDPrev)):
        return True

    print("Metering Data updation failed")
    return False

# %% [markdown]
# # Menu Based Cells

# %%
c = None

while c != 0:
    print("0. Exit")
    print("1. Add SM and NAN")
    print("2. Bi-directional Authentication")
    print("3. Generate Session Key")
    print("4. Get Bill")
    c = int(input("Enter your choice: "))

    if c == 1:
        sm_id = input("SM id: ")
        nan_id = input("nan id: ")
        sm_key = input("sm_key: ")
        nan_key = input("nan_key: ")
        print(phase1(sm_id, nan_id, sm_key, nan_key))
    if c == 2:
        sm_id = input("SM id: ")
        session_key = input("session_key: ")
        print(phase2(sm_id, sm_key))
    if c == 3:
        sm_id = input("SM id: ")
        sm_key = input("sm_key: ")
        print(phase3(sm_id, sm_key))
    if c == 4:
        session_key = input("session_key: ")
        PSID = input("PSID: ")
        MDCurr = int(input("MDCurr: "))
        print(phase4(session_key, PSID, MDCurr))

# %% [markdown]
# Test Cells

# %%
# phase1("00", "00", "00", "00")

# %%
# phase2("00", "00")

# %%
# phase3("00", "00")

# %%
# phase4("00", "00", 100)


