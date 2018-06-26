#!/usr/bin/env python3
import sys
import argparse
import struct
import binascii
import hashlib


class TCPAEvent:
    def __init__(self,
                 pcr_index, event_type, pcr_value, event_size, event_data):
        self.pcr_index = pcr_index
        self.event_type = event_type
        self.pcr_value = pcr_value
        self.event_size = event_size
        self.event_data = event_data
        self.valid = self.__validate()

    def __validate(self):
        h = hashlib.sha1()
        h.update(self.event_data)
        data_digest = h.digest()
        return self.pcr_value == data_digest

    def __str__(self):
        return "{:<3} {:<8x} {} {:<4} {:<5} {}".format(
            self.pcr_index,
            self.event_type,
            binascii.hexlify(self.pcr_value).decode(),
            self.event_size,
            self.valid,
            self.event_data[:30])


class TCPAParser(struct.Struct):
    def __init__(self, bpath):
        super().__init__("<II20sI")
        self.bpath = bpath

    def __iter__(self):
        with open(self.bpath, "rb") as bfile:
            while True:
                br = bfile.read(self.size)
                if not br:
                    break
                us = self.unpack(br)
                event = TCPAEvent(*us, bfile.read(us[3]))
                yield event

class PCR:
    def __init__(self, pcrnum):
        self.pcrnum = pcrnum
        if (pcrnum >= 17 and pcrnum <= 22):
            self.value = b"\xFF" * 20
        else:
            self.value = b"\x00" * 20
        self.__hex()

    def __hex(self):
        self.hval = binascii.hexlify(self.value).decode().upper()

    def update(self, value):
        h = hashlib.sha1()
        h.update(self.value + value)
        self.value = h.digest()
        self.__hex()

    def __str__(self):
        return "PCR-{:02d}: {}".format(
            self.pcrnum,
            " ".join([self.hval[i:i+2] for i in range(0, len(self.hval), 2)]))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TPM binary measurement parser.")
    parser.add_argument("-f",
                        default="/sys/kernel/security/tpm0/binary_bios_measurements",
                        metavar="binary_bios_measurements_file",
                        dest="bfile",
                        help="binary_bios_measurements file path")
    parser.add_argument("-r",
                        default=list(),
                        action="append",
                        nargs=2,
                        metavar=("ID", "SHA1HASH"),
                        dest="replacelist",
                        help="Replace event ID pcr_value with SHA1HASH. Could be used multiple times.")
    args = parser.parse_args()

    tcpa_data = list()
    pcrs = list()

    for p in range(24):
        pcrs.append(PCR(p))

    for event in TCPAParser(args.bfile):
        tcpa_data.append(event)

    for ev_id, pcr_val in args.replacelist:
        try:
            ev_id = int(ev_id)
            if len(pcr_val) != 40:
                print("Replacement ID {} hash length error!".format(ev_id))
                sys.exit(1)
            print("Replacing event ID {} hash {} with {}".format(
                ev_id,
                binascii.hexlify(tcpa_data[ev_id].pcr_value).decode(),
                pcr_val))
            tcpa_data[ev_id].pcr_value = binascii.unhexlify(pcr_val)
        except (TypeError, ValueError):
            print("Replacement ID {} value error!".format(ev_id))
            sys.exit(1)
        except IndexError:
            print("Replacement ID {} is out of event index!".format(ev_id))
            sys.exit(1)

    for event in tcpa_data:
        pcrs[event.pcr_index].update(event.pcr_value)

    print("{:<3} {:<3} {:<8} {:<40} {:<4} {} {}".format(
        "Num", "PCR", "EV_type", "PCR_value", "Size", "Valid", "Data"))
    for num, event in enumerate(tcpa_data):
        print("{:<3} {}".format(num, event))

    print()
    print("Final PCRs:")
    for p in pcrs:
        print(p)
