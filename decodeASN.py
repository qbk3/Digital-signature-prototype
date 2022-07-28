from pyasn1.codec.der import decoder
from os.path import exists, basename

from structs import Key, SignatureSequence


with open("./keyslist/MyGostParamSet2.key", 'rb') as key_f:
    data = key_f.read()
    struct, _ = decoder.decode(data, asn1Spec=Key())
    with open("./keyslist/MyGostParamSet2.key.txt", 'w') as keyw_f:
        keyw_f.write(str(struct))
    print(struct.prettyPrint())

# with open("./testdata/test.txt.sign", 'rb') as sign_f:
#     struct, _ = decoder.decode(sign_f.read(), asn1Spec=SignatureSequence())
#     print('\nRead ASN.1 file:\n')
#     print(struct.prettyPrint())
