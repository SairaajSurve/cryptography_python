from qiskit import *
import math
import numpy as np
import hashlib
from qiskit.tools.visualization import circuit_drawer

# delta parameter
delta = 1/8

# length of secret
m = 1

# length of hash
k = 1

n = m + k

N = math.ceil(4*n*(1+delta))

# error rate
error_rate = 0.5

simulator = Aer.get_backend('qasm_simulator')

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

def sqdsc(key):

    # Step 1
    
    # generate random states of A batch
    A = np.random.randint(4, size=N)
    
    # circuit for communication
    circuit = QuantumCircuit(N, N)
    
    for idx, elem in enumerate(A):
        circuit = encodeQubits(elem, circuit, idx)
    
    # Step 2
    
    # S batch
    
    S = np.random.choice(N, N//2, replace=False)
    S.sort()
    # T batch
    
    T = []
    
    for i in range(N):
        if i not in S:
            T.append(i)
    
    T = np.array(T)
    
    # sm decesion to measure S
    toMeasureS = np.random.randint(2, size=N//2)
    
    tempS = zip(S, toMeasureS)
    
    # measurement of qubits in S by sm

    sec_tested = 0

    for i, d in tempS:
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

    tempS = zip(S, toMeasureS)

    for i, d in tempS:
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
        return None
    
    # step 3

    circuit.barrier()

    # generating B batch

    B = []

    for t in T:
        if A[t] <= 1:
            B.append(t)
    
    B = np.array(B)
    
    if len(B) < m:
        print("Line 103: len(B) < m. Protocol Aborted")
        return None


    # message and hash generation

    M = key

    H_of_M = bin(int(hashlib.sha512(M.encode('utf-8')).hexdigest(), 16))[2:2+(len(B)-m)]

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
    h_prime = M_prime_hat[m:]

    H_of_M_prime = bin(int(hashlib.sha512(M_prime.encode('utf-8')).hexdigest(), 16))[2:2+(len(B)-m)]

    if H_of_M_prime != h_prime:
        print("Line 147: Hashes dont match. Protocol Aborted")
        return None

    return circuit

circuit_drawer(sqdsc("1"), output='mpl', filename='sqdsc2.png')
