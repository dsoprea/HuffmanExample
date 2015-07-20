## Description

For the purpose of an example, I wrote a complete routine to encode and decode data using a Huffman code.


## Features

- We will actually produce binary data (as opposed to strings of 1s and 0s for simplicity).
- We show how to walk the tree to build the encoding table.
- We show how to walk the tree to decode the Huffman-encoded data.
- We show how to preorder-serialize the Huffman tree.
- We show a method of storing the serialized tree (having an arbitrary size) and encoded data (having an arbitrary number of bits) to a file-stream, as well as how to read it back.


## Notes

- This project is Python 3.4 compatible.
- We use the [bitarray](https://github.com/ilanschnell/bitarray) project to build our streams, one bit at a time. It is a natively implemented, efficient solution.


## Overview

### Encoding

The following steps are involved in encoding:

1. Count the frequency of characters in the file.
2. Build a Huffman tree using the frequency table.
3. Assign prefixes to symbols using the Huffman tree.
4. Iterating through the data, lookup the prefix for each character and combine.
5. Serialize the Huffman tree (a balanced binary tree). We do it using a preorder format.
6. Store the serialized tree to the file (along with any markers required to extract during decode). For our implementation, we prefix it with the length and a NULL.
7. Store the encoded data (along with any markers required to extract during decode). For our implementation, we append a "1" bit. This way, when we convert the bit-array to bytes and zeroes are added, we can trim the right amount (along with the "1").


### Decoding

The following steps are involved in decoding:

1. Identify the tree-length.
2. Extract the tree.
3. Unserialize the tree.
4. Extract the encoded data into a *bitarray*, from just after the tree to the end of the file.
5. Pop bits off the end of the encoded data until the first "1" has been discarded.
6. Starting from the root of the tree, descend left and right through the tree until we encounter a value/leaf node, push the symbol, and repeat.
7. Verify that we didn't end-up mid-tree, and return.


## Examples

### test_steps

This example runs through all of the individual steps and looks like the following:

```python
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
```

Output:

```
(Dump) Raw:

54 68 69 73 20 69 73 20 61 20 74 65 73 74 2e 20
54 68 61 6e 6b 20 79 6f 75 20 66 6f 72 20 6c 69
73 74 65 6e 69 6e 67 2e 0a

Weights:
{10: 1,
 32: 7,
 46: 2,
 84: 2,
 97: 2,
 101: 2,
 102: 1,
 103: 1,
 104: 2,
 105: 4,
 107: 1,
 108: 1,
 110: 3,
 111: 2,
 114: 1,
 115: 4,
 116: 3,
 117: 1,
 121: 1}

Tree:

LEFT>
. LEFT>
. . LEFT>
. . . VALUE=(69) [i]
. . RIGHT>
. . . VALUE=(73) [s]
. RIGHT>
. . LEFT>
. . . LEFT>
. . . . VALUE=(54) [T]
. . . RIGHT>
. . . . VALUE=(65) [e]
. . RIGHT>
. . . LEFT>
. . . . LEFT>
. . . . . VALUE=(66) [f]
. . . . RIGHT>
. . . . . VALUE=(72) [r]
. . . RIGHT>
. . . . LEFT>
. . . . . VALUE=(6c) [l]
. . . . RIGHT>
. . . . . VALUE=(a) []
RIGHT>
. LEFT>
. . LEFT>
. . . LEFT>
. . . . VALUE=(6f) [o]
. . . RIGHT>
. . . . VALUE=(61) [a]
. . RIGHT>
. . . LEFT>
. . . . VALUE=(74) [t]
. . . RIGHT>
. . . . VALUE=(6e) [n]
. RIGHT>
. . LEFT>
. . . VALUE=(20) []
. . RIGHT>
. . . LEFT>
. . . . LEFT>
. . . . . LEFT>
. . . . . . VALUE=(6b) [k]
. . . . . RIGHT>
. . . . . . VALUE=(79) [y]
. . . . RIGHT>
. . . . . VALUE=(68) [h]
. . . RIGHT>
. . . . LEFT>
. . . . . VALUE=(2e) [.]
. . . . RIGHT>
. . . . . LEFT>
. . . . . . VALUE=(75) [u]
. . . . . RIGHT>
. . . . . . VALUE=(67) [g]

Encoding:
{'20 ': bitarray('110'),
 '2e .': bitarray('11110'),
 '54 T': bitarray('0100'),
 '61 a': bitarray('1001'),
 '65 e': bitarray('0101'),
 '66 f': bitarray('01100'),
 '67 g': bitarray('111111'),
 '68 h': bitarray('11101'),
 '69 i': bitarray('000'),
 '6b k': bitarray('111000'),
 '6c l': bitarray('01110'),
 '6e n': bitarray('1011'),
 '6f o': bitarray('1000'),
 '72 r': bitarray('01101'),
 '73 s': bitarray('001'),
 '74 t': bitarray('1010'),
 '75 u': bitarray('111110'),
 '79 y': bitarray('111001'),
 'a ': bitarray('01111')}

Encoded characters:

0100 11101 000 001 110 000 001 110 1001 110 1010 0101 001 1010 11110 110 0100 11101 1001 1011 111000 110 111001 1000 111110 110 01100 1000 01101 110 01110 000 001 1010 0101 1011 000 1011 111111 11110 01111

(Dump) Encoded:

4e 83 81 d3 a9 4d 7b 27 66 f8 dc c7 d9 90 dc e0
69 6c 5f fe 7c

(Dump) Decoded:

54 68 69 73 20 69 73 20 61 20 74 65 73 74 2e 20
54 68 61 6e 6b 20 79 6f 75 20 66 6f 72 20 6c 69
73 74 65 6e 69 6e 67 2e 0a

Decoded text:

b'This is a test. Thank you for listening.\n'
```

### test_encode_to_filedata

This example uses some utility functions to build a complete file-image and looks like the following::

```python
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
```

Output:

```
(Dump) Clear bytes:

54 68 69 73 20 69 73 20 61 20 74 65 73 74 2e 20
54 68 61 6e 6b 20 79 6f 75 20 66 6f 72 20 6c 69
73 74 65 6e 69 6e 67 2e 0a

(Dump) Encoded bytes:

4e 83 81 d3 a9 4d 7b 27 66 f8 dc c7 d9 90 dc e0
69 6c 5f fe 7c

(Dump) Encoded file-data:

38 00 00 00 00 01 69 01 73 00 00 01 54 01 65 00
00 01 66 01 72 00 01 6c 01 0a 00 00 00 01 6f 01
61 00 01 74 01 6e 00 01 20 00 00 00 01 6b 01 79
01 68 00 01 2e 00 01 75 01 67 4e 83 81 d3 a9 4d
7b 27 66 f8 dc c7 d9 90 dc e0 69 6c 5f fe 7c

(Dump) Recovered encoded bytes:

4e 83 81 d3 a9 4d 7b 27 66 f8 dc c7 d9 90 dc e0
69 6c 5f fe 7c

(Dump) Recovered decoded bytes:

54 68 69 73 20 69 73 20 61 20 74 65 73 74 2e 20
54 68 61 6e 6b 20 79 6f 75 20 66 6f 72 20 6c 69
73 74 65 6e 69 6e 67 2e 0a
```
