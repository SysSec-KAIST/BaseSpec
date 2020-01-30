from basespec.analyze_spec import check_spec
from basespec.structs.l3msg import IeInfo, L3MsgInfo, L3ProtInfo

# EMM protocol
pd = 7

# EMM attach accept message
msg_type = 0x42

# Build a message
# The information should be extracted from embedded message structures in the binary.
IE_list = []
IE_list.append(IeInfo(msg_type, name="", iei=0, min=1, max=1, imperative=True))
IE_list.append(IeInfo(msg_type, name="", iei=0, min=1, max=1, imperative=True))
IE_list.append(IeInfo(msg_type, name="", iei=0, min=1, max=1, imperative=True))
IE_list.append(IeInfo(msg_type, name="", iei=0, min=6, max=96, imperative=True))
#IE_list.append(IeInfo(msg_type, name="", iei=0, min=0, max=32767, imperative=True)) #missing
IE_list.append(IeInfo(msg_type, name="", iei=0x50, min=11, max=11, imperative=False))
IE_list.append(IeInfo(msg_type, name="", iei=0x13, min=5, max=5, imperative=False))
IE_list.append(IeInfo(msg_type, name="", iei=0x23, min=5, max=8, imperative=False))
IE_list.append(IeInfo(msg_type, name="", iei=0x53, min=1, max=1, imperative=False))
IE_list.append(IeInfo(msg_type, name="", iei=0x4A, min=1, max=99, imperative=False)) #invalid
IE_list.append(IeInfo(msg_type, name="", iei=0xFF, min=5, max=5, imperative=False)) #unknown
attach_accept_msg = L3MsgInfo(pd, msg_type, name="Attach accept", direction="DL", ie_list=IE_list)

# Build protocol
EMM_prot = L3ProtInfo(pd, [attach_accept_msg])

l3_list = [EMM_prot]

# Compare with specification
check_spec(l3_list, pd)
