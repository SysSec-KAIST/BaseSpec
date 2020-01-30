from basespec import parse_spec
spec_msgs = parse_spec.get_spec_msgs() # Format: msgs[pd][msg_type] = ie_list
emm_msgs = spec_msgs[7] # 7 : the type of EPS Mobility Management
smc_ie_list = emm_msgs[0x5d] # 0x5d : the type of SECURITY MODE COMMAND
