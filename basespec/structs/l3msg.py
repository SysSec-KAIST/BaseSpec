class IeInfo:
    def __init__(self, msg_type, name, iei, min, max, imperative):
        self.type = msg_type
        self.name = name
        self.iei = iei
        self.min = min
        self.max = max
        self.imperative = imperative

    def __repr__(self):
        if self.imperative:
            imper = 'imperative'
        else:
            imper = 'non-imperative'
        res = "<IE {} (0x{:02X}, 0x{:02X}) {}".format(imper, self.type, self.iei, self.name)
        length = (
            str(self.min)
            if self.min == self.max
            else "{}-{}".format(self.min, self.max)
        )
        res += " len: {}".format(length)
        res += ">"
        return res


class L3MsgInfo:
    def __init__(self, pd, msg_type, name, direction, ie_list):
        self.pd = pd
        self.type = msg_type
        self.direction = direction
        self.ie_list = ie_list  # A list of IeInfo instances.
        self.ie_num = len(ie_list)

    def __repr__(self):
        res = "L3Msg (0x{:02X})".format(self.type)
        res += " {} {}".format(self.direction, self.ie_num)
        for idx, ie in enumerate(self.ie_list):
            res += "\n\t0x{:02x}: {}".format(idx, ie)
        res += "\n"
        return res


class L3ProtInfo:
    def __init__(self, pd, msg_list):
        self.pd = pd
        self.msg_list = msg_list  # A list of L3MsgInfo instances.
        self.msg_num = len(msg_list)

    def __repr__(self):
        res = "L3Prot ({}) {} msg".format(self.pd, len(self.msg_list))
        return res
