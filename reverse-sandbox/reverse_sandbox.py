#!/usr/bin/env python

"""
iOS/OS X sandbox decompiler

Heavily inspired from Dion Blazakis' previous work
    https://github.com/dionthegod/XNUSandbox/tree/master/sbdis
Excellent information from Stefan Essers' slides and work
    http://www.slideshare.net/i0n1c/ruxcon-2014-stefan-esser-ios8-containers-sandboxes-and-entitlements
    https://github.com/sektioneins/sandbox_toolkit
"""

import sys
import struct
import logging.config
import argparse
import os
import operation_node
import sandbox_filter
import sandbox_regex
import subprocess
from filters import Filters

import tqdm

REGEX_TABLE_OFFSET = 2
REGEX_COUNT_OFFSET = 4
VARS_TABLE_OFFSET = 6
VARS_COUNT_OFFSET = 8
NUM_PROFILES_OFFSET = 10

logging.config.fileConfig("logger.config")
logger = logging.getLogger(__name__)

ios18_struct = struct.Struct('<HHBBBBBBHHH')
PROFILE_OPS_OFFSET = 8
OPERATION_NODE_SIZE = 8
INDEX_SIZE = 2

class SandboxData():
    def __init__(self,
        ios18_struct_size, header, op_nodes_count, sb_ops_count, vars_count,
        states_flag, states_count, profile_flag, unknown_byte, num_profiles, re_count, instructions_count) -> None:

        self.data_file = None

        self.header_size = ios18_struct_size
        self.type = header
        self.op_nodes_count = op_nodes_count
        self.sb_ops_count = sb_ops_count
        self.vars_count = vars_count
        self.states_flag = states_flag
        self.states_count = states_count
        self.profile_flag = profile_flag
        self.unknown_byte = unknown_byte
        self.num_profiles = num_profiles
        self.regex_count = re_count
        self.instructions_count = instructions_count

        # offsets
        self.regex_table_offset = self.header_size
        self.vars_offset = self.regex_table_offset + (self.regex_count * INDEX_SIZE)
        self.states_offset = self.vars_offset + (self.vars_count * INDEX_SIZE)
        self.states_high_offset = self.states_offset + (self.states_flag * INDEX_SIZE)
        self.profile_flag_offset = self.states_high_offset + (self.states_count * INDEX_SIZE)
        self.instructions_offset = self.profile_flag_offset + (self.profile_flag * INDEX_SIZE)

        self.profiles_offset = self.instructions_offset + (self.instructions_count * INDEX_SIZE)

        self.profiles_end_offset = self.profiles_offset + (self.num_profiles * ((self.sb_ops_count * INDEX_SIZE) + PROFILE_OPS_OFFSET))
        self.operation_nodes_size = self.op_nodes_count * OPERATION_NODE_SIZE
        self.operation_nodes_offset = self.profiles_end_offset

        if self.type != 0x8000:
            self.operation_nodes_offset += self.sb_ops_count * INDEX_SIZE

        align_delta = self.operation_nodes_offset & 7
        if align_delta != 0:
            self.operation_nodes_offset += 8 - align_delta

        self.base_addr = self.operation_nodes_offset + self.operation_nodes_size

        # data
        self.regex_list = None
        self.global_vars = None
        self.policies = None
        self.sb_ops = None
        self.operation_nodes = None
        self.ops_to_reverse = None

    def __repr__(self) -> str:
        # states_count_high: {hex(self.states_high_offset)}
        return f"""
                struct_size: {hex(self.header_size)}
                header: {hex(self.type)}
                op_nodes_count: {hex(self.op_nodes_count)}
                sb_ops_count: {hex(self.sb_ops_count)}
                vars_count: {hex(self.vars_count)}
                states_count: {hex(self.states_count)}
                num_profiles: {hex(self.num_profiles)}
                re_table_count: {hex(self.regex_count)}
                instuctions_count: {hex(self.instructions_count)}

                regex_table_offset: {hex(self.regex_table_offset)}
                pattern_vars_offset: {hex(self.vars_offset)}
                states_offset: {hex(self.states_offset)}
                states_high_offset: {hex(self.states_high_offset)}
                instuctions_offset: {hex(self.instructions_offset)}
                profiles_offset: {hex(self.profiles_offset)}
                profiles_end_offset: {hex(self.profiles_end_offset)}
                operation_nodes_offset: {hex(self.operation_nodes_offset)}
                operation_nodes_size: {hex(self.operation_nodes_size)}
                base_adrr: {hex(self.base_addr)}
                """

def node_to_c(node):
    queue = [node]
    processed = []

    out = ""
    while len(queue):
        node = queue[0]
        del queue[0]

        out += "node_%x:; // %r\n" % (node.offset, node.raw)
        if node.terminal:
            out += node.c_repr() + "\n\n"
            continue

        out += "if (%s) goto node_%x;\nelse goto node_%x;\n\n" % (node.c_repr(), node.non_terminal.match_offset, node.non_terminal.unmatch_offset)

        if node.non_terminal.match not in processed:
            processed += [node.non_terminal.match]
            queue += [node.non_terminal.match]

        if node.non_terminal.unmatch not in processed:
            processed += [node.non_terminal.unmatch]
            queue += [node.non_terminal.unmatch]

    return out.strip()

def parse_profile(infile) -> SandboxData:
    infile.seek(0)

    # ios 18
    header, \
    op_nodes_count, \
    sb_ops_count, \
    vars_count, \
    states_flag, \
    states_count, \
    profile_flag, \
    unknown_byte, \
    num_profiles, \
    re_count, \
    instructions_count \
        = ios18_struct.unpack(infile.read(16))

    sandbox_data = SandboxData(
        ios18_struct.size, header, op_nodes_count, sb_ops_count, vars_count,
        states_flag, states_count, profile_flag, unknown_byte, num_profiles, re_count, instructions_count)

    sandbox_data.data_file = infile

    print(sandbox_data)

    return sandbox_data


def extract_string_from_offset(f, offset, base_addr) -> str:
    """Extract string (literal) from given offset."""
    f.seek(offset * 8 + base_addr)
    len = struct.unpack("<H", f.read(2))[0] - 1
    return '%s' % f.read(len).decode("utf-8")


def create_operation_nodes(infile, sandbox_data, keep_builtin_filters):
    # Read sandbox operations.
    sandbox_data.operation_nodes = operation_node.build_operation_nodes(infile, sandbox_data.op_nodes_count)
    logger.info("operation nodes")

    for op_node in sandbox_data.operation_nodes:
        op_node.convert_filter(sandbox_filter.convert_filter_callback, infile, sandbox_data, keep_builtin_filters)
    logger.info("operation nodes after filter conversion")


    return sandbox_data.operation_nodes

def process_profile(infile, outfname, sb_ops, ops_to_reverse, op_table, operation_nodes, c_output, macho):
    if macho:
        c_output = True
    if c_output:
        outfile = open(outfname.strip() + ".c", "wt")
    else:
        out_fname = os.path.join(outfname.strip() + ".sb")
        outfile = open(out_fname, "wt")

    # Extract node for 'default' operation (index 0).
    default_node = operation_node.find_operation_node_by_offset(operation_nodes, op_table[0])
    if not default_node.terminal:
        print("Warning: default node is not terminal")


    if c_output:
        outfile.write("extern long allow(const char *);\n")
        outfile.write("extern long deny(const char *);\n")
        
        outfile.write("extern long unparsed_filter();\n")
        outfile.write("extern long subpath();\n")
        outfile.write("extern long subpath_prefix();\n")
        
        for f in Filters.filters.values():
            name = f["name"];
            if name == "":
                name = "literal"
            for suffix in ["", "_regex", "_literal", "_prefix"]:
                outfile.write("extern long %s%s();\n" % (name.replace("-", "_"), suffix))
    else:
        outfile.write("(version 1)\n")
        if default_node.terminal:
            outfile.write("(%s default)\n" % (default_node.terminal))
        else:
            outfile.write("(deny default)\n")
    
    # For each operation expand operation node.
    for idx in range(1, len(op_table)):
        offset = op_table[idx]
        operation = sb_ops[idx]
        # Go past operations not in list, in case list is not empty.
        if ops_to_reverse:
            if operation not in ops_to_reverse:
                continue

        node = operation_node.find_operation_node_by_offset(operation_nodes, offset)

        if not node:
            continue

        if c_output:
            outfile.write("long %s()\n{\n" % (operation.replace("-", "_").replace("*", "$"),))
            outfile.write(node_to_c(node))
            outfile.write("\n}\n\n")
            continue

        g = operation_node.build_operation_node_graph(node, default_node)
        if g:
            rg = operation_node.reduce_operation_node_graph(g)
            rg.str_simple_with_metanodes()
            default_is_allow = default_node.terminal.is_allow() if default_node.terminal else False
            rg.print_vertices_with_operation_metanodes(operation, default_is_allow, outfile)
        else:
            if node.terminal:
                default_type = default_node.terminal.type if default_node.terminal else None
                if node.terminal.type != default_type:
                    outfile.write("(%s %s)\n" % (node.terminal, operation))
                else:
                    modifiers_type = [key for key, val in node.terminal.db_modifiers.items() if len(val)]
                    if modifiers_type:
                        outfile.write("(%s %s)\n" % (node.terminal, operation))

    outfile.close()
    
    if macho:
        # -O > 0 generates a lot of variable assignments that hinder decompilation readability
        subprocess.run(["clang", outfname.strip() + ".c", "-g", "-O0", "-undefined", "dynamic_lookup", "-Wno-everything", "-o", outfname.strip()])

def display_sandbox_profiles(infile, profiles_offset, num_profiles, base_addr):
    logger.info("Printing sandbox profiles from bundle")

    names = ""
    for i in range(0, num_profiles):

        infile.seek(profiles_offset + 0x188 * i)
        name_offset = struct.unpack("<H", infile.read(2))[0]
        name = extract_string_from_offset(infile, name_offset, base_addr)

        names += "\n" + name

    logger.info("Found %d sandbox profiles." % num_profiles)


def get_global_vars(f, vars_offset, num_vars, base_address):
    global_vars = []

    next_var_pointer = vars_offset
    for i in range(0, num_vars):
        f.seek(next_var_pointer)
        var_offset = struct.unpack("<H", f.read(2))[0]
        f.seek(base_address + (var_offset * 8))
        len = struct.unpack("H", f.read(2))[0]
        s = f.read(len-1)
        global_vars.append(s.decode('utf-8'))
        next_var_pointer += 2

    logger.info("global variables are {:s}".format(", ".join(s for s in global_vars)))
    return global_vars

def get_policies(f, offset, count, base_address):

    policies_str = []
    f.seek(offset)
    policies = struct.unpack("<%dH" % (count), f.read(2*count))
    next_var_pointer = offset
    for i in range(0, count):
        f.seek(next_var_pointer)
        # f.seek(policies[i])
        # var_offset = struct.unpack("<H", f.read(2))[0]
        # f.seek(base_address + (var_offset * 8))
        f.seek(base_address + (policies[i] * 8))
        len = struct.unpack("H", f.read(2))[0]
        s = f.read(len - 1)
        policies_str.append(s.decode('utf-8'))
        next_var_pointer += 2

    logger.info("policies/ states variables are {:s}".format(", ".join(s for s in policies_str)))
    return policies_str

def read_sandbox_operations(parser, args, sandbox_data) -> None:
    sb_ops = [l.strip() for l in open(args.operations_file)]
    sandbox_data.sb_ops = sb_ops

    num_sb_ops = len(sb_ops)
    logger.info("num_sb_ops: %d", num_sb_ops)

    ops_to_reverse = []
    if args.operation:
        for op in args.operation:
            if op not in sb_ops:
                parser.print_usage()
                print ("unavailable operation: {}".format(op))
                sys.exit(1)
            ops_to_reverse.append(op)
        sandbox_data.ops_to_reverse = ops_to_reverse

def parse_regex_list(infile, sandbox_data):
    logger.debug("\n\nregular expressions:\n")
    regex_list = []

    if sandbox_data.regex_count > 0:
        infile.seek(sandbox_data.regex_table_offset)
        re_offsets_table = struct.unpack("<%dH" % sandbox_data.regex_count, infile.read(2 * sandbox_data.regex_count))

        for offset in re_offsets_table:
            infile.seek(offset * 8 + sandbox_data.base_addr)
            re_length = struct.unpack("<H", infile.read(2))[0]
            re = struct.unpack("<%dB" % re_length, infile.read(re_length))
            re_debug_str = "re: [", ", ".join([hex(i) for i in re]), "]"
            logger.debug(re_debug_str)
            regex_list.append(sandbox_regex.parse_regex(re))

    logger.info(regex_list)
    sandbox_data.regex_list = regex_list

def populate_enabled_profile_flags(infile, read_address_out):
    infile.seek(read_address_out)
    flag = struct.unpack("<Bx", infile.read(2))[0]
    read16_result = struct.unpack("<H", infile.read(2))[0]
    if flag:
        result = 0
        states_flag = struct.unpack("<Q", infile.read(8))[0]
        # integer object?
        return read16_result + states_flag
    else:
        result = 0
        states_flag = 0
        return 0 + 0

def profile_populate_base_profile(infile, sandbox_data, offset_2, offset_4):
    if offset_2 & 0x400000000:
        print("== flag error")
        return 0
    # read_address_out = sandbox_data.base_addr + (offset_4 * 8)
    if offset_4:
        base_profile_name = extract_string_from_offset(infile, offset_4, sandbox_data.base_addr)
        return base_profile_name

def parse_state_flag(infile, sandbox_data, state_flag, offset_4, offset_6):
    if state_flag & 0x800:
        # profile_struct->re_table_count) = state_flag (offset 2)
        # read address at profile + 6
        read_address_out = sandbox_data.base_addr + (offset_6 * 8)
        # populate_enabled_profile_flags
        profile_flag_out = populate_enabled_profile_flags(infile, read_address_out)
        if state_flag:
            if not profile_flag_out:
                # might be an error
                state_flag &= ~0x800
                # profile_struct->states_flag_7 = 0;
            else:
                if not profile_flag_out >> 61 and 8 * profile_flag_out <= 0xff: # sanity check
                    if 8 * profile_flag_out < sandbox_data.states_count: # sanity check
                        sandbox_data.states_count = 8 * profile_flag_out
                        # save profile offset + 2 in unknown_q4




def main():
    """Reverse Apple binary sandbox file to SBPL (Sandbox Profile Language) format.

    Sample run:
        python reverse_sandbox.py -r 7.1.1 container.sb.bin
        python reverse_sandbox.py -r 7.1.1 -d out container.sb.bin
        python reverse_sandbox.py -r 7.1.1 -d out container.sb.bin -n network-inbound network-outbound
        python reverse_sandbox.py -r 9.0.2 -d out sandbox_bundle_iOS_9.0 -n network-inbound network-outbound -p container
    """

    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="path to the binary sandbox profile")
    parser.add_argument("-r", "--release", help="iOS release version for sandbox profile", required=True)
    parser.add_argument("-o", "--operations_file", help="file with list of operations", required=True)
    parser.add_argument("-p", "--profile", nargs='+', help="profile to reverse (for bundles) (default is to reverse all operations)")
    parser.add_argument("-n", "--operation", nargs='+', help="particular operation(s) to reverse (default is to reverse all operations)")
    parser.add_argument("-d", "--directory", help="directory where to write reversed profiles (default is current directory)")
    parser.add_argument("-psb", "--print_sandbox_profiles", action="store_true", help="print sandbox profiles of a given bundle (only for iOS versions 9+)")
    parser.add_argument("-kbf", "--keep_builtin_filters", help="keep builtin filters in output", action="store_true")
    parser.add_argument("-c", "--c_output", help="output a C file rather than Scheme", action="store_true")
    parser.add_argument("-m", "--macho", help="generate a reversible Mach-O file (implies --c_output)", action="store_true")
    

    args = parser.parse_args()

    if args.filename is None:
        parser.print_usage()
        print ("no sandbox profile/bundle file to reverse")
        sys.exit(1)

    if args.directory:
        out_dir = args.directory
    else:
        out_dir = os.getcwd()

    infile = open(args.filename, "rb")

    sandbox_data = parse_profile(infile)
    parse_regex_list(infile, sandbox_data)

    read_sandbox_operations(parser, args, sandbox_data)



    if args.print_sandbox_profiles:
        if sandbox_data.type == 0x8000:
            display_sandbox_profiles(infile, sandbox_data.profiles_offset, sandbox_data.num_profiles, sandbox_data.base_addr)
        else:
            print ("cannot print sandbox profiles list; filename {} is not a sandbox bundle".format(args.filename))
        sys.exit(0)

    ## parse common structure ##

    logger.info("{:d} global vars at offset {}".format(sandbox_data.vars_count, sandbox_data.vars_offset))
    sandbox_data.global_vars = get_global_vars(infile, sandbox_data.vars_offset, sandbox_data.vars_count, sandbox_data.base_addr)
    # sandbox_data.policies = get_policies(infile, sandbox_data.instructions_offset, sandbox_data.instructions_count)
    sandbox_data.states_arr = get_policies(infile, sandbox_data.states_offset, sandbox_data.states_flag, sandbox_data.base_addr)
    sandbox_data.states_high_arr = get_policies(infile, sandbox_data.states_high_offset, sandbox_data.states_count, sandbox_data.base_addr)
    sandbox_data.policies = get_policies(infile, sandbox_data.states_offset, sandbox_data.states_flag,
                                           sandbox_data.base_addr)
    sandbox_data.policies.extend(get_policies(infile, sandbox_data.states_high_offset, sandbox_data.states_count,
                                                sandbox_data.base_addr))
    # sandbox_data.states_high_arr = get_policies(infile, sandbox_data.instructions_offset, sandbox_data.instructions_count,
    #                                             sandbox_data.base_addr)
    # sandbox_data.profiles_names = get_policies(infile, sandbox_data.profiles_offset, sandbox_data.profile_flag, sandbox_data.base_addr)
    # Place file pointer to start of operation nodes area.
    logger.info("number of operation nodes: %u" % sandbox_data.op_nodes_count)
    infile.seek(sandbox_data.operation_nodes_offset)

    operation_nodes = create_operation_nodes(infile, sandbox_data, args.keep_builtin_filters)

    # In case of sandbox profile bundle, go through each profile.
    if sandbox_data.type == 0x8000:
        logger.info("using profile bundle")

        profile_size = (sandbox_data.sb_ops_count * 2) + 2 + 2 + 2 + 2 # + name + policy index + unknown + unknown

        # read profiles
        for i in range(0, sandbox_data.num_profiles):
            profile_offset = sandbox_data.profiles_offset + profile_size * i
            infile.seek(profile_offset)
            # 0
            name_offset = struct.unpack("<H", infile.read(2))[0]
            orig_offset = infile.tell()

            name = extract_string_from_offset(infile, name_offset, sandbox_data.base_addr)

            infile.seek(orig_offset)
            # 2
            state_flag = struct.unpack("<H", infile.read(2))[0]
            # 4
            base_profile_offset = struct.unpack("<H", infile.read(2))[0]

            infile.seek(orig_offset)
            base_profile_name = profile_populate_base_profile(infile, sandbox_data, state_flag, base_profile_offset)

            infile.seek(orig_offset)
            # 6 idk
            offset_6 = struct.unpack("<H", infile.read(2))[0]
            parse_state_flag(infile, sandbox_data, state_flag, base_profile_offset, offset_6)

            # Go past profiles not in list, in case list is defined.
            if args.profile:
                if name not in args.profile:
                    continue
            logger.info("profile name (offset 0x%x): %s" % (name_offset, name))

            infile.seek(sandbox_data.profiles_offset + profile_size * i + PROFILE_OPS_OFFSET) # name + flags + policy index

            # operands to read for each profile
            op_table = struct.unpack("<%dH" % sandbox_data.sb_ops_count, infile.read(2 * sandbox_data.sb_ops_count))

            name = name.replace('/', '_')
            out_folder_name = os.path.join(out_dir, name)

            if not os.path.exists(out_folder_name):
                os.mkdir(out_folder_name)

            out_fname = os.path.join(out_folder_name, name)

            with open(out_fname + ".metadata", "wb") as f:
                f.write((f"base_profile: {base_profile_name}\n\nstates_flag: {hex(sandbox_data.states_flag)}"
                        f"\n\npolicies:\n\t{sandbox_data.policies}\n\nstates:\n\t{sandbox_data.states_arr}"
                        f"\n\nstates_high_bit:\n\t{sandbox_data.states_high_arr}\n").encode('utf-8'))

            # with open(out_fname + ".bin", "wb") as f:
            #     pos = infile.tell()
            #     infile.seek(sandbox_data.profiles_offset + profile_size * i)
            #     f.write(infile.read(profile_size))
            #     infile.seek(pos)

            process_profile(infile, out_fname, sandbox_data.sb_ops, sandbox_data.ops_to_reverse, op_table, operation_nodes, args.c_output, args.macho)

    # global profile
    else:
        infile.seek(sandbox_data.profiles_offset)

        op_table = struct.unpack("<%dH" % sandbox_data.sb_ops_count, infile.read(2 * sandbox_data.sb_ops_count))
        infile.seek(sandbox_data.operation_nodes_offset)
        logger.info("number of operation nodes: %d" % sandbox_data.op_nodes_count)

        out_fname = os.path.join(out_dir, os.path.splitext(os.path.basename(args.filename))[0])
        process_profile(infile, out_fname, sandbox_data.sb_ops, sandbox_data.ops_to_reverse, op_table, operation_nodes, args.c_output, args.macho)

    infile.close()


if __name__ == "__main__":
    sys.exit(main())
