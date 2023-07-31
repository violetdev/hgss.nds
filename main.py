

def checksum(data):
    ck = 0
    for i in range(0, len(data), 4):
        ck += int(int(data[i:i+4], 16).to_bytes(2, 'little').hex(), 16)
    return hex(ck)[2:].zfill(4)[-4:]

def orderBlocks(shiftValue, A, B, C, D):
    block_order = [
                [ A,B,C,D ],[ A,B,D,C ],[ A,C,B,D ],[ A,C,D,B ],
                [ A,D,B,C ],[ A,D,C,B ],[ B,A,C,D ],[ B,A,D,C ],
                [ B,C,A,D ],[ B,C,D,A ],[ B,D,A,C ],[ B,D,C,A ],
                [ C,A,B,D ],[ C,A,D,B ],[ C,B,A,D ],[ C,B,D,A ],
                [ C,D,A,B ],[ C,D,B,A ],[ D,A,B,C ],[ D,A,C,B ],
                [ D,B,A,C ],[ D,B,C,A ],[ D,C,A,B ],[ D,C,B,A ]
                ]
    return block_order[shiftValue]

def invOrderBlocks(shiftValue, A, B, C, D):
    block_order = [
                [ A,B,C,D ],[ A,B,D,C ],[ A,C,B,D ],[ A,D,B,C ],
                [ A,C,D,B ],[ A,D,C,B ],[ B,A,C,D ],[ B,A,D,C ],
                [ C,A,B,D ],[ D,A,B,C ],[ C,A,D,B ],[ D,A,C,B ],
                [ B,C,A,D ],[ B,D,A,C ],[ C,B,A,D ],[ D,B,A,C ],
                [ C,D,A,B ],[ D,C,A,B ],[ B,C,D,A ],[ B,D,C,A ],
                [ C,B,D,A ],[ D,B,C,A ],[ C,D,B,A ],[ D,C,B,A ]
                ]
    return block_order[shiftValue]

def getShiftValue(pv):
    #return (int(pv, 16) >> 13) & 31
    return ((int(pv, 16) & 0x3E000) >> 0xD) % 24

def crypt(msg, seed):
    seed = hex((0x41C64E6D * (int(seed, 16) & 0xFFFFFFFFFFFFFFFF) + 0x6073))[2:]
    key = hex(int(seed, 16) >> 16)[2:][-4:]
    key = int(key, 16).to_bytes(2, 'little').hex()
    key = int(key, 16)
    msg = int(msg, 16)
    return hex(key ^ msg)[2:].zfill(4), seed


# Read .nds file
with open('new.nds', 'rb') as f:
    save = f.read().hex()
    f.close()

# Header
PARTY_OFFSET = 0x2889D0 * 2 # PARTY_OFFSET = 0x98 * 2
PARTY_LENGTH = 472
PV = save[PARTY_OFFSET:PARTY_OFFSET+8]
PV = int(PV, 16).to_bytes(4, 'little').hex()
shift_value = getShiftValue(PV)
CHECKSUM = save[PARTY_OFFSET+12:PARTY_OFFSET+16]
CHECKSUM = int(CHECKSUM, 16).to_bytes(2, 'little').hex()

# Checksum encrypted block
ENCRYPTED = save[PARTY_OFFSET+16:PARTY_OFFSET+PARTY_LENGTH]
ENCRYPTED = ENCRYPTED[0:256]

# Decrypt battle stats
EBS = save[PARTY_OFFSET+272:PARTY_OFFSET+PARTY_LENGTH]
seed = PV
UBS = ''
for i in range(0, len(EBS), 4):
    msg, seed = crypt(EBS[i:i+4], seed)
    UBS += msg

# Decrypt data
seed = CHECKSUM
UNENCRYPTED = ''
for i in range(0, len(ENCRYPTED), 4):
    # if i % 64 == 0:
    #     print('-----------')
    msg, seed = crypt(ENCRYPTED[i:i+4], seed)
    # print(ENCRYPTED[i:i+4], '-->', msg, seed)
    UNENCRYPTED += msg

A, B, C, D = invOrderBlocks(shift_value, UNENCRYPTED[0:64], UNENCRYPTED[64:128], UNENCRYPTED[128:192], UNENCRYPTED[192:256])
UNENCRYPTED = A + B + C + D

####
# Max IVs, Max spa, spe EVs
evs = '000004fcfc00'
ivs = 'ffffff3f'
UNENCRYPTED = UNENCRYPTED[:32] + evs + UNENCRYPTED[32+len(evs):]
UNENCRYPTED = UNENCRYPTED[:96] + ivs + UNENCRYPTED[96+len(ivs):]
# Shiny and Nature (Timid)
PID, SID = UNENCRYPTED[10:12] + UNENCRYPTED[8:10], UNENCRYPTED[14:16] + UNENCRYPTED[12:14]
p, s = int(PID, 16), int(SID, 16)
for i in range(2**32):
    newPV = hex(i)[2:].zfill(8)
    p1, p2 = int(newPV[:4], 16), int(newPV[4:], 16)
    if p ^ s ^ p1 ^ p2 < 8 and i % 25 == 10:
        shift_value = getShiftValue(int(newPV, 16).to_bytes(4, 'little').hex())
        break
####

# Encrypt data
A, B, C, D = orderBlocks(shift_value, UNENCRYPTED[0:64], UNENCRYPTED[64:128], UNENCRYPTED[128:192], UNENCRYPTED[192:256])
UNENCRYPTED = A + B + C + D
ck = checksum(UNENCRYPTED)
seed = ck
ENCRYPTED = ''
for i in range(0, len(UNENCRYPTED), 4):
    msg, seed = crypt(UNENCRYPTED[i:i+4], seed)
    ENCRYPTED += msg

# Encryt battle stats
seed = newPV
EBS = ''
for i in range(0, len(UBS), 4):
    msg, seed = crypt(UBS[i:i+4], seed)
    EBS += msg

# Print encrypted hex string
newPV = int(newPV, 16).to_bytes(4, 'little').hex()
ENCRYPTED = newPV + '0000' + ck[2:4] + ck[0:2] + ENCRYPTED + EBS
print(ENCRYPTED)


### IV Test
# IV_data = int(UNENCRYPTED[96:96+8], 16).to_bytes(4, 'little').hex()
# IV = bin(int(IV_data, 16))[2:]
# print(IV)
# # IV = '00111111111111111111111111111111'
# print(int(IV[2:7],2), int(IV[7:12],2), int(IV[12:17],2), int(IV[17:22],2), int(IV[22:27],2), int(IV[27:32],2))
# print(hex(int(IV,2)))
