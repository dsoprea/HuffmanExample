#!/usr/bin/env python3.4

import queue
import io
import collections
import struct
import pprint
import math

import bitarray

_NODE = \
    collections.namedtuple(
        '_NODE', [
            # Only populated if an inner-node.
            'left',
            'right',

            # Only populated if a leaf-node.
            'value',
        ])

_ENCODING = \
    collections.namedtuple(
        '_ENCODING', [
            'weights',
            'table',
            'tree',
        ])

def _make_bitarray(*args):
    """A factory, just in case we want to control endianness."""

    return bitarray.bitarray(*args)

def _dump_hex(title, b):
    slice_size_b = 16

    print("(Dump) {0}".format(title))
    print('')

    for i in range(0, len(b), slice_size_b):
        slice_ = b[i:i + slice_size_b]
        print(' '.join([hex(x)[2:].rjust(2, '0') for x in slice_]))

    print('')

def _dump_binary(title, b):
    slice_size_b = 8

    print("Dump: {0}".format(title))
    print('')

    for i in range(0, len(b), slice_size_b):
        slice_ = b[i:i + slice_size_b]
        print(' '.join([bin(x)[2:].rjust(8, '0') for x in slice_]))

    print('')


class TreeUtility(object):
    """Manage a prefix-ordered serialized representation of a Huffman tree."""

    def __serialize_inner(self, node, b):
        if node.value is not None:
            has_value = True
            value = node.value
        else:
            has_value = False
            value = None

        b.append(int(has_value))

        if has_value is True:
            b.append(value)

        if has_value is False:
            self.__serialize_inner(node.left, b)
            self.__serialize_inner(node.right, b)

    def serialize(self, tree):
        b = bytearray()
        self.__serialize_inner(tree, b)

        return b

    def __unserialize_inner(self, serialized, offset, tab=0):
        has_value = bool(serialized[offset])
        offset += 1

        # This is nicer to look at than Python's ternary syntax.

        if has_value is True:
            value = serialized[offset]
            offset += 1

            left_node = None
            right_node = None
        else:
            value = None

            (left_node, offset) = self.__unserialize_inner(serialized, offset, tab + 1)
            (right_node, offset) = self.__unserialize_inner(serialized, offset, tab + 1)

        n = _NODE(value=value, left=left_node, right=right_node)
        return (n, offset)

    def unserialize(self, serialized):
        (n, offset) = self.__unserialize_inner(serialized, 0)

        return n

    def print_tree(self, tree, depth=0):
        tab = '. ' * depth

        if tree.value is None:
            print(tab + 'LEFT>')
            self.print_tree(tree.left, depth + 1)
            print(tab + 'RIGHT>')
            self.print_tree(tree.right, depth + 1)
        else:
            encoded = hex(tree.value)[2:]
            print(tab + 'VALUE=({0}) [{1}]'.format(encoded, chr(tree.value).strip()))


class PriorityQueueItem(object):
    def __init__(self, priority, node):
        self.__priority = priority
        self.__node = node

    def __lt__(self, o):
        return self.__priority < o.__priority

    def __eq__(self, o):
        return self.__priority == o.__priority

    @property
    def priority(self):
        return self.__priority

    @property
    def node(self):
        return self.__node


class Encoding(object):
    def __calculate_weights(self, text):
        """Build a dictionary of weights/frequencies for the symbols in the 
        given text/list.
        """

        w = {}
        for c in text:
            try:
                w[c] += 1
            except KeyError:
                w[c] = 1

        return w

    def __get_tree(self, weights, text):
        """Build the Huffman tree."""

        pq = queue.PriorityQueue()

        for c, w in weights.items():
            n = _NODE(left=None, right=None, value=c)
            item = PriorityQueueItem(w, n)
            pq.put(item)

        first_item = None
        while 1:
            try:
                first_item = pq.get(block=False)
                second_item = pq.get(block=False)
            except queue.Empty:
                break

            # Combine both of the lowest-priority nodes to render a new node of 
            # the combined priority.
            new_priority = first_item.priority + second_item.priority
            n = _NODE(left=first_item.node, right=second_item.node, value=None)
            
            item = PriorityQueueItem(new_priority, n)
            pq.put(item)

        return first_item.node

    def __register_encoding(self, encoding, prefix, node):
        """Recursively traverse the tree and assign prefixes to symbols."""

        if node.value is not None:
            if prefix == '':
                encoding[node.value] = '0'
            else:
                encoding[node.value] = prefix
        else:
            self.__register_encoding(
                encoding, 
                prefix + _make_bitarray([0]), 
                node.left)
            
            self.__register_encoding(
                encoding, 
                prefix + _make_bitarray([1]), 
                node.right)

    def __build_encoding(self, root):
        encoding = {}
        self.__register_encoding(encoding, _make_bitarray(), root)

        return encoding

    def get_encoding(self, text):
        w = self.__calculate_weights(text)
        t = self.__get_tree(w, text)
        e = self.__build_encoding(t)

        return _ENCODING(weights=w, table=e, tree=t)

def encode_to_debug_string(encoding, original):
    """Return a string of space-separated binary, for debugging. The last 
    byte will NOT be padded.
    """

    parts = [encoding[c] for c in original]

    bit_phrases = [
        ''.join([str(int(b)) for b in p]) 
        for p 
        in parts]

    return ' '.join(bit_phrases)

def encode(encoding, original):
    """Given the encoding table, return a bytes object with the encoded string.
    """

    assert \
        issubclass(original.__class__, (bytes, bytearray, list)), \
        "Original data must be a bytes object or a list."

    b = _make_bitarray()
    for c in original:
        part = encoding[c]
        b.extend(part)

    # We might get some extra zeros for alignment to a byte boundary when 
    # we convert to bytes, so we'll need this one to be able to trim them
    # when we decode.
    b.extend([1])

    return b.tobytes()

def decode(tree, encoded):
    """Given the Huffman tree, render the original data."""

    assert \
        issubclass(encoded.__class__, (bytes, bytearray, list)), \
        "Original data must be a bytes object or a list."

    stream = _make_bitarray()
    stream.frombytes(encoded)

    # Pop the trailing zero-bits and the one termination bit.
    while stream.pop() is False:
        pass

    i = 0
    ptr = None
    b = bytearray()
    while i < len(stream):
        bit = stream[i]
        if ptr is None:
            ptr = tree
        
        # Branch left if the next bit is 0. Else, right.
        ptr = ptr.left if bit is False else ptr.right

        # If we're on a leaf, push the value of the leaf and jump back to 
        # root.
        if ptr.value is not None:
            b.append(ptr.value)
            ptr = None

        i += 1

    assert ptr is None, "We didn't correctly decode the encoded content."

    return b

def encode_with_preamble(tree, encoded_data):
    """Combine a serialized representation of the tree with the encoded 
    data to render something that can be written to a file.
    """

    tu = TreeUtility()

    tree_serialized = bytearray(tu.serialize(tree))
    len_ = len(tree_serialized)

    len_hex = hex(len_)[2:]
    if len(len_hex) % 2 == 1:
        len_hex = '0' + len_hex

    len_parts = bytearray([int(len_hex[i:i+2], 16) for i in range(0, len(len_hex), 2)])

    b = bytearray()
    b.extend(len_parts)
    b.append(0)
    b.extend(tree_serialized)
    b.extend(encoded_data)

    return bytes(b)

def decode_with_preamble(encoded_complete):
    """Decode the combined serialized-tree and encoded-data."""

    tu = TreeUtility()

    # Search the first ten-bytes for the end of the bytes representing the 
    # length of the tree. We arbitrarily choose (10) as an impossible 
    # maximum (just in case someone gives us bad/irrelevant data).
    pivot = encoded_complete[:10].index(0)

    offset = 0

    # Read the tree length.

    len_parts = encoded_complete[offset:pivot]
    len_hex = ''.join([hex(x)[2:] for x in len_parts])
    len_ = int(len_hex, 16)

    offset += pivot + 1

    # Read three serialized tree.

    tree_serialized = encoded_complete[offset:offset + len_]
    tree = tu.unserialize(tree_serialized)
    offset += len_

    # Read the encoded data.

    encoded_data = encoded_complete[offset:]

    return (tree, encoded_data)

def test_get_data():
    clear_bytes = b"""\
This is a test. Thank you for listening.
"""

    return clear_bytes

def test_steps():
    clear_bytes = test_get_data()
    _dump_hex("Raw:", clear_bytes)

    tu = TreeUtility()

    # Build encoding table and tree.

    he = Encoding()
    encoding = he.get_encoding(clear_bytes)

    print("Weights:\n{0}".format(pprint.pformat(encoding.weights)))
    print('')

    print("Tree:")
    print('')

    tu.print_tree(encoding.tree)
    print('')

    flat_encoding_table = { 
        (hex(c)[2:] + ' ' + chr(c).strip()): b
        for (c, b) 
        in encoding.table.items() }

    print("Encoding:\n{0}".format(pprint.pformat(flat_encoding_table)))
    print('')

    # Encode the data.

    print("Encoded characters:\n\n{0}\n".\
          format(encode_to_debug_string(encoding.table, clear_bytes)))

    encoded_bytes = encode(encoding.table, clear_bytes)
    _dump_hex("Encoded:", encoded_bytes)

    # Decode the data.

    decoded_bytes_list = decode(encoding.tree, encoded_bytes)
    decoded_bytes = bytes(decoded_bytes_list)

    assert \
        clear_bytes == decoded_bytes, \
        "Decoded does not equal the original."

    _dump_hex("Decoded:", decoded_bytes)

    print("Decoded text:")
    print('')
    print(decoded_bytes)
    print('')

    # Serialize and unserialize tree.

    serialized_tree = tu.serialize(encoding.tree)
    unserialized_tree = tu.unserialize(serialized_tree)

    decoded_bytes_list2 = decode(unserialized_tree, encoded_bytes)
    decoded_bytes2 = bytes(decoded_bytes_list2)

    assert \
        clear_bytes == decoded_bytes2, \
        "Decoded does not equal the original after serializing/" \
        "unserializing the tree."

def test_encode_to_filedata():
    clear_bytes = test_get_data()
    _dump_hex("Clear bytes:", clear_bytes)

    # Build encoding table and tree.

    he = Encoding()
    encoding = he.get_encoding(clear_bytes)

    # Encode the data.

    encoded_bytes = encode(encoding.table, clear_bytes)
    _dump_hex("Encoded bytes:", encoded_bytes)

    # Multiplex to produce raw file-data.

    file_data = encode_with_preamble(encoding.tree, encoded_bytes)
    _dump_hex("Encoded file-data:", file_data)

    # Demultiplex the file-data.

    r = decode_with_preamble(file_data)
    (unserialized_tree, recovered_encoded_bytes) = r
    _dump_hex("Recovered encoded bytes:", recovered_encoded_bytes)

    decoded_bytes = decode(unserialized_tree, recovered_encoded_bytes)
    _dump_hex("Recovered decoded bytes:", decoded_bytes)

    assert \
        clear_bytes == decoded_bytes, \
        "Decoded file-data does not match original."

if __name__ == '__main__':
    test_steps()
#    test_encode_to_filedata()
