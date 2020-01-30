import re
import sys
import os

from collections import defaultdict

# TODO: handle special cases
SHORT_PROT = [
    "VBS/VGCS",
    "Synchronization channel information",
]


# This may need to run on Linux
def convert_txt(fname_in, fname_out=""):
    if not fname_out:
        fname_out = os.path.splitext(fname_in)[0] + ".txt"

    if not os.path.exists(fname_out):
        ext = os.path.splitext(fname_in)[-1]
        if ext == ".doc":
            os.system('antiword -w 0 "{}" > "{}"'.format(fname_in, fname_out))
        elif ext == ".pdf":
            os.system('pdftotext -layout "{}" "{}"'.format(fname_in, fname_out))

    return fname_out


def read_data(fname):
    with open(fname, "r", encoding="ascii", errors="ignore") as f:
        data = f.read()

    # incorrectly converted character
    data = data.replace("\xa0", " ")

    # TS 44.018
    data = data.replace("ACK.", "ACKNOWLEDGE")
    data = data.replace("NOTIFICATION RESPONSE", "NOTIFICATION/RESPONSE")
    data = data.replace(
        "SYSTEM INFORMATION TYPE 2 quater", "SYSTEM INFORMATION TYPE 2quater"
    )
    data = data.replace("SYSTEM INFORMATION 15", "SYSTEM INFORMATION TYPE 15")
    data = data.replace("EXTENDED MEASUREMENT ORDER", " EXTENDED MEASUREMENT ORDER")
    data = data.replace("CDMA 2000", "CDMA2000")
    # data = data.replace('00010110  MBMS ANNOUNCEMENT', '00110101  MBMS ANNOUNCEMENT')

    # TS 24.008
    #    data = data.replace('DETACH REQUEST', ' DETACH REQUEST')
    #    data = data.replace('DETACH ACCEPT', ' DETACH ACCEPT')
    #    data = data.replace('Detach ACCEPT', ' Detach ACCEPT')
    data = data.replace(" Contents of Service Request", " Service Request")
    data = data.replace(" Contents of Service Accept", " Service Accept")
    data = data.replace(" Contents of Service Reject", " Service Reject")
    data = data.replace(
        "  Authentication and ciphering req", "  Authentication and ciphering request"
    )
    data = data.replace(
        "  Authentication and ciphering resp", "  Authentication and ciphering response"
    )
    data = data.replace(
        "  Authentication and ciphering rej", "  Authentication and ciphering reject"
    )
    data = data.replace("activation rej.", "activation reject")
    data = data.replace("request(Network", "request (Network")
    data = data.replace("request(MS", "request (MS")
    data = data.replace("TABLE", "Table")
    data = data.replace("AUTHENTICATION FAILURE..", "AUTHENTICATION FAILURE")
    # Check "Facility(simple recall alignment)" length "2-"
    lines = data.splitlines()

    return lines


def get_direction(lines, idx):
    # find direction
    tmp_idx = idx
    while "direction" not in lines[tmp_idx].lower() and tmp_idx >= 0:
        tmp_idx -= 1

    assert "direction" in lines[tmp_idx].lower()

    s = lines[tmp_idx].lower()
    if (
        "network to mobile" in s
        or "to ms" in s
        or "to ue" in s
        or "-> ms " in s
        or "dl" in s
    ):
        direction = "DL"
    elif (
        "mobile station to network" in s
        or "mobile to network" in s
        or "ms to" in s
        or "ue to" in s
        or "ms ->" in s
        or "ul" in s
    ):
        direction = "UL"
    elif "both" in s:
        direction = "both"
    else:
        direction = None

    return direction


def parse_msg_content(lines):
    in_table = False
    direction = None
    ie_list = []
    idx = 0
    msgs = defaultdict(list)
    msg_name = ""

    while idx < len(lines):
        line = lines[idx]

        if not line:
            idx += 1
            continue

        if "Table" in line:
            # Handle messages whose name is too long.
            # ts 44.018: INTER SYSTEM TO CDMA2000 HANDOVER
            # ts 24.008: MODIFY PDP CONTEXT REQUEST, MODIFY PDP CONTEXT ACCEPT
            if "message content" not in line and re.search(
                "(message )?content[s]?$", lines[idx + 1].strip()
            ):
                line = line.strip() + " " + lines[idx + 1].strip()
                idx += 1

            # Handle messages whose name is too long.
            # ts 44.018: EC IMMEDIATE ASSIGNMENT TYPE 1
            if "information element" not in line and re.search(
                "(information )?element[s]?$", lines[idx + 1].strip()
            ):
                line = line.strip() + " " + lines[idx + 1].strip()

            # Handle messages whose name is an exception.
            # ts 24.008: SETUP
            line = re.sub("(.* message content) ?\(.*to.*direction\)", "\g<1>", line)
        #            if 'SETUP message content' in line and 'direction' in line:
        #                line = re.sub('(SETUP message content).*', '\g<1>', line)

        if re.match("^[ \|]*Table.*message content", line):
            # If there exist another table, we skip it
            if in_table:
                if ie_list:
                    msgs[msg_name.lower()].append((direction, ie_list))

                # These are not standard L3 messages.
                # only one exception is special case for IMMEDIATE ASSIGNMENT as below:
                # Table 9.1.18.1a: IMMEDIATE ASSIGNMENT message content (MTA
                # Access Burst or Extended Access Burst Method only)
                #
                # We skip this case as it is a special case.
                idx += 1
                in_table = False
                continue

            in_table = True
            # g = re.match('^\s*Table [0-9\.\:]+', line)
            msg_name = re.search("[: ]([A-Za-z\-\/0-9 \(\)]+) message content", line)
            msg_name = msg_name.group().strip().replace(":", "")
            # msg_name = msg_name.replace(':', '').strip()
            # table_name = table_name.split()[-1]
            msg_name = msg_name.replace("message content", "").strip()
            # msg_name = (table_name, msg_name)

            direction = get_direction(lines, idx)
            ie_list = []

            idx += 1
            continue

        if re.match("^\s*Table.*information elements[ ]*$", line):
            # If there exist another table, we skip it
            if in_table:
                if ie_list:
                    msgs[msg_name.lower()].append((direction, ie_list))

                # These are not standard L3 messages.
                idx += 1
                in_table = False
                continue

            in_table = True
            # g = re.match('^\s*Table [0-9\.\:]+', line)
            msg_name = re.search(" ([A-Za-z\-\/0-9 ]+) information elements", line)
            msg_name = msg_name.group().strip()
            # table_name = table_name.split()[-1]
            msg_name = msg_name.replace("information elements", "").strip()
            # msg_name = (table_name, msg_name)

            direction = get_direction(lines, idx)
            ie_list = []

            idx += 1
            continue

        if not in_table:
            idx += 1
            continue

        if re.match("^\d+\.\d+", line):
            if ie_list:
                msgs[msg_name.lower()].append((direction, ie_list))
            else:
                # this is not a proper standard L3 message
                # print('{} may not be parsed properly.'.format(msg_name))
                pass

            in_table = False
            direction = None
            ie_list = []
            idx += 1
            continue

        if "ETSI" in line:
            idx += 1
            continue

        # dummy line
        # IEI Information Element Type/Reference Presence Format Length
        # ts 44.018 has 'length', not 'Length'
        if (
            "presence" in lines[idx].lower()
            and "format" in lines[idx].lower()
            and "length" in lines[idx].lower()
        ):
            idx += 1
            continue

        fields = lines[idx].split("|")
        fields = list(filter(lambda x: x, fields))

        if len(fields) != 6:
            idx += 1
            continue

        fields = list(map(lambda x: x.strip(), fields))
        iei, ie_name, ref, presence, ie_format, length = fields
        if not presence or not ie_format:
            idx += 1
            continue

        # incompatible spec
        length = length.replace("octets", "").strip()
        length = length.replace("octet", "").strip()
        length = length.replace("(", "-").strip()
        length = length.replace(" ", "")
        # length = length.replace('?', 'n')

        # convert spec error
        if length.endswith("-"):
            length = length + "n"

        if not length:
            length = "1/2"

        # spec error
        if "n" in length and "-" not in length:
            length = length.replace("n", "-n")

        if length == "1/23/2":
            length = "1/2-3/2"

        # For SMS (type 9) - CM - RP messages. rest 5 bits are spare
        if length == "3bits":
            length = "1"

        # For SMS (type 9) - some messages use '<=' operator
        if length.startswith("-"):
            length = "1" + length

        # convert spec parsing error
        try:
            if 3000 < int(length) < 4000:
                length = length[0] + "-" + length[1:]
        except:
            pass

        ie_list.append([ie_name, iei, ref, presence, ie_format, length])

        idx += 1

    return msgs


def parse_msg_type(lines, pdf=False):
    in_table = False
    idx = 0
    msgs = defaultdict(list)
    prefix = ""

    while idx < len(lines):
        line = lines[idx]

        if not line:
            idx += 1
            continue

        if re.match("^\s*Table.*Message types", line):
            in_table = True
            table_name, class_name = line.split(":")
            table_name = table_name.split()[-1]
            if "for" in class_name:
                class_name = class_name.replace("Message types for", "").strip()
            else:
                class_name = ""
            prefix = ""

            # dummy line
            # IEI Information Element Type/Reference Presence Format Length
            idx += 1
            continue

        if not in_table:
            idx += 1
            continue

        if re.match("^\d+\.\d+", line):
            in_table = False
            idx += 1
            continue

        if "ETSI" in line:
            idx += 1
            continue

        msg = lines[idx]

        if pdf:
            msg_type = re.match("^[01x\- ]+", msg)
        else:
            msg_type = re.match("^\|[\|\.01x\- ]+", msg)

        if not msg_type:
            idx += 1
            continue

        msg_type = msg_type.group()
        msg_name = msg.replace(msg_type, "")
        msg_name = msg_name.replace("|", "").strip()
        msg_name = msg_name.replace(":", "").strip()

        msg_type = msg_type.replace("|", "")
        msg_type = msg_type.replace(" ", "").strip()
        msg_type = msg_type.replace(".", "-")

        if "reserved" in msg_name.lower():
            idx += 1
            continue

        if len(msg_type) < 4:
            idx += 1
            continue

        msg_cnt = sum(map(lambda x: x == "-", msg_type))

        if msg_cnt > 2:
            prefix = msg_type
            if class_name:
                sub_class_name = class_name + "-" + msg_name
            else:
                sub_class_name = msg_name
            idx += 1
            continue

        if "x" in msg_type:
            idx += 1
            continue

        msg_type = msg_type.replace("-", "")
        if len(msg_type) < 8 and prefix:
            prefix_cnt = sum(map(lambda x: x == "-", prefix))
            if len(msg_type) != prefix_cnt:
                idx += 1
                continue

            msg_type = prefix[: (8 - len(msg_type))] + msg_type
            msg_type = msg_type.replace("x", "0")

        # print(msg_type, prefix, msg_name)
        #        if len(msg_type) != 8:
        #            msg_type = msg_type.rjust(8, '0')
        #            import pdb; pdb.set_trace()
        #            idx += 1
        #            continue

        assert msg_name not in msgs

        if prefix:
            msgs[msg_name] = [msg_type, sub_class_name]
        else:
            msgs[msg_name] = [msg_type, class_name]
        idx += 1

    return msgs


def handle_exception_24011(msgs):
    """
    # ts 4.011, RP messages use
    RP messages are included in CP messages
    0 0 0 ms -> n RP-DATA
    0 0 1 n -> ms RP-DATA
    0 1 0 ms -> n RP-ACK
    0 1 1 n -> ms RP-ACK
    1 0 0 ms -> n RP-ERROR
    1 0 1 n -> ms RP-ERROR
    1 1 0 ms -> n RP-SMMA
    """

    cp_class_name = "short message and notification transfer on CM"
    rp_class_name = "short message and notification transfer on CM-RP messages"
    types = {
        # 'cp-data' [1, cp_Class_name] is embedding below messages
        "rp-data": [0, rp_class_name],
        "rp-data": [1, rp_class_name],
        "rp-ack": [2, rp_class_name],
        "rp-ack": [3, rp_class_name],
        "rp-error": [4, rp_class_name],
        "rp-error": [5, rp_class_name],
        "rp-smma": [6, rp_class_name],
        "cp-ack": [4, cp_class_name],
        "cp-error": [16, cp_class_name],
    }

    return msgs, types


# complementary parser
def parse(input_fname, input_fname2=""):
    txt_name = convert_txt(input_fname)
    lines = read_data(txt_name)
    msgs = parse_msg_content(lines)
    types = parse_msg_type(lines, ".pdf" in input_fname)

    # complementary step
    if input_fname2:
        # analyze pdf to extract types
        txt_name = convert_txt(input_fname2)
        lines = read_data(txt_name)
        # msgs2 = parse_msg_content(lines)
        types2 = parse_msg_type(lines, ".pdf" in input_fname2)

        for key, val in types2.items():
            if key not in types:
                types[key] = val

    if "24011" in input_fname or "24.011" in input_fname:
        msgs, types = handle_exception_24011(msgs)

    total = defaultdict(list)
    for msg_name, (msg_type, class_name) in types.items():
        orig_name = msg_name
        msg_name = msg_name.lower()
        if "reserved" in msg_name:
            continue

        if msg_name not in msgs:
            continue

        if isinstance(msg_type, str):
            msg_type = int(msg_type, 2)
        total[class_name].append([msg_type, orig_name, msgs[msg_name]])

    return total


def parse_all():
    path = os.path.abspath(os.path.dirname(__file__))
    file_list = [
        ["24008-f80.doc", "ts_124008v150800p.pdf"],
        ["24011-f30.doc", ""],
        ["24080-f10.doc", ""],
        ["24301-f80.doc", "ts_124301v150800p.pdf"],
        ["44018-f50.doc", ""],
    ]

    total = {}
    for f1, f2 in file_list:
        f1 = os.path.join(path, "spec", f1)
        if f2:
            f2 = os.path.join(path, "spec", f2)
        msgs = parse(f1, f2)
        for key, val in msgs.items():
            total[key] = val

    return total


def get_spec_msgs():
    msgs = parse_all()
    # =============================
    # Message types
    # =============================
    nas_prots = {
        "EPS session management": 2,
        "Call Control and call related SS messages": 3,
        "GTTP messages": 4,
        "Mobility Management": 5,
        "Radio Resource management": 6,
        "EPS mobility management": 7,
        "GPRS mobility management": 8,
        "short message and notification transfer": 9,
        "GPRS session management": 10,
        "Miscellaneous message group": 11,
        "Clearing messages": 11,
    }

    spec_map = {}
    for nas_name, nas_type in nas_prots.items():
        spec_map[nas_type] = {}

    for class_name, vals in sorted(msgs.items()):
        if "-" in class_name:
            class_name, sub_class_name = class_name.split("-")
        else:
            sub_class_name = ""

        target_nas_type = None
        for nas_name, nas_type in nas_prots.items():
            if nas_name in class_name:
                target_nas_type = nas_type
                break

        assert target_nas_type is not None

        for msg_type, msg_name, ie_list in vals:
            if msg_type not in spec_map[target_nas_type]:
                spec_map[target_nas_type][msg_type] = []
            spec_map[target_nas_type][msg_type].append(
                [class_name, sub_class_name, msg_name, ie_list]
            )

    return spec_map


def main():
    if len(sys.argv) < 2:
        msgs = parse_all()

    elif len(sys.argv) == 2:
        input_fname = sys.argv[1]
        msgs = parse(input_fname)

    elif len(sys.argv) > 2:
        input_fname = sys.argv[1]
        input_fname2 = sys.argv[2]
        msgs = parse(input_fname, input_fname2)

    for class_name, vals in sorted(msgs.items()):
        for msg_type, msg_name, msgs2 in sorted(vals):
            for direction, ie_list in msgs2:
                for ie in ie_list:
                    ie_name, iei, ref, presence, ie_format, length = ie
                    if direction == "UL":
                        print(
                            class_name,
                            "->",
                            msg_name,
                            "(UL) ->",
                            ie_name,
                            ie_format,
                            length,
                        )
                    elif direction == "DL":
                        print(
                            class_name,
                            "->",
                            msg_name,
                            "(DL) ->",
                            ie_name,
                            ie_format,
                            length,
                        )
                    elif direction == "both":
                        print(
                            class_name,
                            "->",
                            msg_name,
                            "(Both) ->",
                            ie_name,
                            ie_format,
                            length,
                        )
                    else:
                        print(
                            class_name,
                            "->",
                            msg_name,
                            "() ->",
                            ie_name,
                            ie_format,
                            length,
                        )
                        assert False


if __name__ == "__main__":
    main()
