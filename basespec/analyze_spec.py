import time
import itertools

from .parse_spec import get_spec_msgs


def flatten(l):
    return list(itertools.chain.from_iterable(l))


def find_ref(spec_map, target_ref, target_pd=None):
    for pd, vals in spec_map.items():
        if target_pd and pd != target_pd:
            continue

        for msg_type, args in vals.items():
            class_name, sub_class_name, msg_name, ie_list = args
            for idx, ie in enumerate(ie_list):
                ie_name, iei, ref, presence, ie_format, length = ie
                if target_ref in ref.lower():
                    print(
                        "NasProt[{}] {} -> {}, {}".format(
                            pd, class_name, sub_class_name, msg_name
                        )
                    )
                    print(
                        "    [{}] {}: iei: {}, presence: {}, format: {}, length: {}".format(
                            idx, ie_name, iei, presence, ie_format, length
                        )
                    )


def print_ie_list(spec_ie_list):
    for idx, ie in enumerate(spec_ie_list):
        ie_name, iei1, ref, spec_presence, spec_format, spec_length = ie
        print("[{}] ({}) {} {} {}".format(idx, iei1, ie_name, spec_format, spec_length))


def sanitize_iei(iei):
    if iei:
        iei = iei.strip("-")
        iei = iei.strip("x")
        if iei == "TBC":
            iei = 0
        elif iei:
            iei = int(iei, 16)
        else:
            iei = 0
    else:
        iei = 0

    return iei


def sanitize_len(len1, len2):
    if len1 == len2:
        msg_length = "{}".format(len1)
    else:
        msg_length = "{}-{}".format(len1, len2)

    return msg_length


def apply_li(spec_ie, bin_ie):
    ie_name, iei1, ref, spec_presence, spec_format, spec_length = spec_ie
    len2_min = bin_ie.min
    len2_max = bin_ie.max

    # ================================================
    # Convert Length
    # ================================================
    # For the length of the specification, the length of IEI, LI is already
    # included in the length. However, for those having length 'n', it is not
    # included. Thus, we calculate them first.
    if "-" in spec_length:
        len1_min, len1_max = spec_length.split("-")
        if len1_max == "?":
            len1_max = "n"
        len1_min = int(len1_min)
        if len1_max == "n":
            if "-E" in spec_format:
                len1_max = 2 ** 16 - 1
            else:
                len1_max = 2 ** 8 - 1

            if "T" in spec_format:
                len1_max += 1
            if "L" in spec_format:
                len1_max += 1
            if "-E" in spec_format:
                len1_max += 1
        else:
            len1_max = int(len1_max)

    elif spec_length == "1/2":
        len1_min = 1
        len1_max = 1

    else:
        len1_min = int(spec_length)
        len1_max = int(spec_length)

    if not (spec_format == "TV" and spec_length == "1"):
        if "T" in spec_format:
            len2_min += 1
            len2_max += 1
        if "L" in spec_format:
            len2_min += 1
            len2_max += 1
        if "-E" in spec_format:
            len2_min += 1
            len2_max += 1

    return len1_min, len1_max, len2_min, len2_max


def compare_ie(spec_ie, bin_ie):
    ie_name, iei1, ref, spec_presence, spec_format, spec_length = spec_ie
    spec_presence = spec_presence.split()[0]
    iei1 = sanitize_iei(iei1)
    iei2 = bin_ie.iei
    len1_min, len1_max, len2_min, len2_max = apply_li(spec_ie, bin_ie)

    bug_str = ""
    if bin_ie.imperative:
        ie_type = 'imperative'
    else:
        ie_type = 'non-imperative'

    # ================================================
    # Check format (LI, Length Indicator) and length
    # ================================================
    # If a length is specified,
    if len1_min != len2_min:
        bug_str += ", {} invalid mismatch (min length)".format(ie_type)
    if len1_max != len2_max:
        bug_str += ", {} invalid mismatch (max length)".format(ie_type)

    return bug_str


def compare_ie_list(pd, msg, spec_msg):
    s = ""
    class_name, sub_class_name, msg_name, spec_direction, spec_ie_list = spec_msg
    # check direction
    if (msg.direction != spec_direction) and (spec_direction != 'both'):
        return s

    # skip common IEs that do not exist in the baseband firmware
    l = 0
    for idx, ie in enumerate(spec_ie_list):
        ie_name, iei, ref, presence, ie_format, length = ie
        if "message type" in ref.lower() or "message type" in ie_name.lower():
            break

    # sms (9) -> nested element exists
    if pd == 9 and msg.type not in [4, 16]:
        spec_ie_list = spec_ie_list
    else:
        spec_ie_list = spec_ie_list[idx + 1 :]

    bin_ie_list = msg.ie_list
    # Filter if bin_ie_list is not implemented yet.
    if len(spec_ie_list) > 0 and len(bin_ie_list) == 0:
        s += "0x{0:x} ({0}) {1} not implemented in pd {2}".format(
            msg.type, msg_name, pd
        )
        return s

    # ================================================
    # First, we divide IE list of the specification to imperatives and
    # non-imperatives.
    # ================================================
    bug_flag = False
    imperatives = []
    nonimperatives = {}
    for idx, ie in enumerate(spec_ie_list):
        ie_name, iei1, ref, spec_presence, spec_format, spec_length = ie
        bug_str = ""

        # Check spec length
        if spec_length == "1/2" and spec_format not in ["V", "TV"]:
            bug_str += ",spec length error"

        # Check presence of the specification
        if (
            "M" not in spec_presence
            and "O" not in spec_presence
            and "C" not in spec_presence
        ):
            bug_str += ",spec presence error"

        # In TS 24.007, 11.2.5 Presence requirements of information elements,
        # only IEs belonging to non-imperative part of a message may have
        # presence requirement C. However, we find special case for conditional
        # IE implementation. That is, there is a message that has an imperative
        # part having IEs of the "C" presence.
        #
        # Protocol: Radio Resource management (PD: 6)
        # Message: IMMEDIATE ASSIGNMENT (DL) (Message Type: 0x3f)
        if pd == 6 and msg.type == 0x3F:
            if "C" in spec_presence and sanitize_iei(iei1) == 0:
                if 'packet channel description' in ie_name.lower():
                    continue
                ie = ie_name, iei1, ref, spec_presence, spec_format, spec_length

        ie_name = ie_name.replace(",", "")
        # imperative / non-imperative is defined by iei, not presence.
        if sanitize_iei(iei1) == 0 and "O" not in spec_presence:
            if "T" in spec_format or "O" in spec_presence:
                bug_str += ",spec format error"

            imperatives.append(ie)

        else:
            if "T" not in spec_format:
                bug_str += ",spec non-imperative format error"

            if sanitize_iei(iei1) in nonimperatives:
                # ts 24.007, 11.2.4
                # A message may contain two or more IEs with equal IEI. Two IEs
                # with the same IEI in a same message must have
                # 1) the same format,
                # 2) when of type 3, the same length.
                # More generally, care should be taken not to introduce
                # ambiguities by using an IEI for two purposes. Ambiguities
                # appear in particular when two IEs potentially immediately
                # successive have the same IEI but different meanings and when
                # both are non-mandatory. As a recommended design rule,
                # messages should contain a single IE of a given IEI.
                ie2 = nonimperatives[sanitize_iei(iei1)]
                ie_name2, iei2, ref2, spec_presence2, spec_format2, spec_length2 = ie2
                if spec_format != spec_format2:  # same format
                    bug_str += ",spec non-imperative same iei format error"

                elif spec_length != spec_length2:  # Type 3
                    assert "-" not in spec_length
                    bug_str += ",spec non-imperative same iei length error"

            else:
                nonimperatives[sanitize_iei(iei1)] = ie

        if bug_str:
            s += "{},{},".format(ie_name, ref)
            s += "{},{},{},{},".format(iei1, spec_presence, spec_format, spec_length)
            s += "-,-,-,-,-"
            s += "," + bug_str.lstrip(",") + "\n"
            bug_flag = True

    # To separate errors from the spec and the baseband binary.
    if s:
        s += "-" * 20 + "\n"

    # ================================================
    # Now we check the IE list in the baseband binary and compare them with the
    # IE list from the spec.
    # ================================================
    iei_done = set()

    for idx, bin_ie in enumerate(bin_ie_list):
        bug_str = ""

        # Fetch corresponding IE from specification
        spec_ie = None

        # The implementation has two rules for representing imperatives.
        # Developers may misunderstood the specification?
        if bin_ie.imperative:
            if imperatives:
                spec_ie = imperatives.pop(0)

            if spec_ie:
                ie_name, iei1, ref, spec_presence, spec_format, spec_length = spec_ie
                ie_name = ie_name.replace(",", "")
                len1_min, len1_max, len2_min, len2_max = apply_li(spec_ie, bin_ie)

                # skipped 1/2 length in binary implementation
                if spec_length == "1/2" and (len2_min != len2_max or len2_max != 1):
                    s += "{},{},".format(ie_name, ref)
                    s += "{},{},{},{},".format(
                        iei1, spec_presence, spec_format, spec_length
                    )
                    s += "-,-,-,-"
                    if "spare half" in ref.lower():
                        s += ",(skipped spare half)"
                    else:
                        s += ",imperative missing mismatch (skipped 1/2)"
                        bug_flag = True
                    s += "\n"

                    if imperatives:
                        spec_ie = imperatives.pop(0)
                    else:
                        spec_ie = None

        else:
            if bin_ie.iei in nonimperatives:
                spec_ie = nonimperatives[bin_ie.iei]
                iei1 = spec_ie[1]
                len1_min, len1_max, len2_min, len2_max = apply_li(spec_ie, bin_ie)

                # This is check for IE type1 having a 4-bit IEI and 4-bit value
                if iei1.endswith("-") and (len2_min != len2_max or len2_max != 1):
                    spec_ie = None
                else:
                    iei_done.add(bin_ie.iei)

        if spec_ie:
            ie_name, iei1, ref, spec_presence, spec_format, spec_length = spec_ie
            ie_name = ie_name.replace(",", "")
            len1_min, len1_max, len2_min, len2_max = apply_li(spec_ie, bin_ie)
            if "/" not in spec_length:
                spec_length = sanitize_len(len1_min, len1_max)
            msg_length = sanitize_len(len2_min, len2_max)
            s += "{},{},".format(ie_name, ref)
            s += "{},{},{},{},".format(iei1, spec_presence, spec_format, spec_length)
            s += "{:02X},{},{},0x{:X}".format(
                bin_ie.iei, bin_ie.imperative, msg_length, bin_ie.type
            )
            bug_str = compare_ie(spec_ie, bin_ie)

        else:
            msg_length = sanitize_len(bin_ie.min, bin_ie.max)
            s += "-,-,"
            s += "-,-,-,-,"
            s += "{:02X},{},{},0x{:X}".format(
                bin_ie.iei, bin_ie.imperative, msg_length, bin_ie.type
            )
            if bin_ie.imperative:
                bug_str = "imperative unknown mismatch"
            else:
                bug_str = "non-imperative unknown mismatch"

        if bug_str:
            s += "," + bug_str.lstrip(",")
            bug_flag = True
        s += "\n"

    # ================================================
    # Check leftovers
    # ================================================
    for spec_ie in imperatives:
        ie_name, iei1, ref, spec_presence, spec_format, spec_length = spec_ie
        ie_name = ie_name.replace(",", "")
        s += "{},{},".format(ie_name, ref)
        s += "{},{},{},{},".format(iei1, spec_presence, spec_format, spec_length)
        s += "-,-,-,-"
        if "spare half" in ref.lower():
            s += ",(skipped spare half)"
            s += "\n"
        else:
            s += ",imperative missing mismatch"
            s += "\n"
            bug_flag = True

    for iei in nonimperatives:
        if iei not in iei_done:
            ie2 = nonimperatives[iei]
            ie_name, iei1, ref, spec_presence, spec_format, spec_length = ie2
            ie_name = ie_name.replace(",", "")
            s += "{},{},".format(ie_name, ref)
            s += "{},{},{},{},".format(iei1, spec_presence, spec_format, spec_length)
            s += "-,-,-,-"
            s += ",non-imperative missing mismatch"
            s += "\n"
            bug_flag = True

    if not bug_flag:
        s = ""

    return s


def check_numbers(l3_msgs):
    total_msgs = 0
    total_ies = 0
    total_iies = 0
    for pd, prot in enumerate(l3_msgs):
        if len(prot.msg_list) == 0:
            continue

        if pd > 12:
            break

        msgs = l3_msgs[pd].msg_list
        print("# of {} msgs: {}".format(pd, len(msgs)))

        ies = flatten(map(lambda x: x.ie_list, msgs))
        iies = list(filter(lambda x: x.imperative, map(lambda x: x[0], ies)))
        print("# of {} msg IEs: {}".format(pd, len(ies)))
        print("# of {} msg imperative IEs: {}".format(pd, len(iies)))

        total_msgs += len(valid_msgs)
        total_ies += len(ies)
        total_iies += len(iies)

    print("# of total msgs: {}".format(total_msgs))
    print("# of total IEs: {}".format(total_ies))
    print("# of total imperative IEs: {}".format(total_iies))


def check_spec(l3_msgs, target_pd=3):
    '''
    check_spec compares l3_msgs from binary with specification.
    It prints comparision results (e.g., mismatches) in CSV format.

    :param l3_msgs: list of basespec.structs.l3msg.L3ProtInfo
                    which is generated based on embedded message structure
                    of the binary.
    :param target_pd: the PD value to analyze.
    '''
    global spec_map
    if "spec_map" not in globals():
        spec_map = get_spec_msgs()

    for prot in l3_msgs:
        pd = prot.pd
        if len(prot.msg_list) == 0:
            continue

        # For DEBUG
        if pd != target_pd:
            continue

        if pd not in spec_map:
            continue

        prot_done = set()
        for msg in prot.msg_list:
            msg_type = msg.type

            if msg_type not in spec_map[pd]:
                print("=" * 20)
                print(
                    "NasProt[{0}] msg_type 0x{1:x} ({1}) not in pd {0}".format(
                        pd, msg_type
                    )
                )
                continue

            # There may exist multiple messages from spec, so we analyze each
            # message and pick the least buggy message.
            spec_msgs = spec_map[pd][msg_type]
            msg_results = {}

            for spec_msg in spec_msgs:
                class_name, sub_class_name, msg_name, msgs = spec_msg
                for direction, ie_list in msgs:
                    spec_msg = (
                        class_name,
                        sub_class_name,
                        msg_name,
                        direction,
                        ie_list,
                    )
                    prot_done.add(msg_type)

                    try:
                        s = compare_ie_list(pd, msg, spec_msg).strip()
                        s_cnt = s.count("error")

                        if direction in msg_results:
                            if s_cnt < msg_results[direction][-1][-1]:
                                msg_results[direction] = (
                                    class_name,
                                    sub_class_name,
                                    msg_name,
                                    (s, s_cnt),
                                )
                        else:
                            msg_results[direction] = (
                                class_name,
                                sub_class_name,
                                msg_name,
                                (s, s_cnt),
                            )
                    except:
                        import traceback

                        print(class_name, sub_class_name, msg_name, direction)
                        traceback.print_exc()

            # Filter the least buggy message
            for direction, (
                class_name,
                sub_class_name,
                msg_name,
                (s, s_cnt),
            ) in msg_results.items():
                if s:
                    print("=" * 20)
                    print(
                        "NasProt[{}] {} -> {}".format(
                            pd, class_name, sub_class_name
                        )
                    )
                    print(
                        "0x{0:x} ({0}) {1} ({2})".format(msg_type, msg_name, direction)
                    )
                    title = "IE Name,Reference,Spec IEI,Spec Presence,Spec Format,Spec Length,"
                    title += "Bin IEI,Bin Imperative,Bin Length,Bin Idx"
                    print(title)
                    print(s)

        # Check messages not implemented in the binary.
        for msg_type in spec_map[pd]:
            if msg_type not in prot_done:
                spec_msg = spec_map[pd][msg_type][0]
                class_name, sub_class_name, msg_name, msgs = spec_msg
                print("=" * 20)
                print(
                    "NasProt[{}] {} -> {}".format(pd, class_name, sub_class_name)
                )
                print(
                    "0x{0:x} ({0}) {1} not implemented in pd {2}".format(
                        msg_type, msg_name, pd
                    )
                )
