MAX_BYTES = 10 # number of bytes needed to encode a 64-bit int

print("define token opbyte (8)")
print("\ttopbit = (7, 7)")
for i in range(MAX_BYTES):
    print("\tv" + str(i) + " = (0, 6)")
print(";\n")

for i in range(1, MAX_BYTES+1):
    definition = "ULeb128: val is "
    for j in range(i-1, -1, -1):
        definition += "topbit = " + str(0 if j == 0 else 1) + " & v" + str(j) + (" " if j == 0 else "; ")
    print(definition)
    valdef = "\t[ val = 0 | v0 "+ ("; " if i==1 else "| ")
    for j in range(1, i):
        valdef += "( v" + str(j) + " << " + str(7 * j) + " ) " + ("; " if j==i-1 else "| ")
    valdef += "]"
    
    print(valdef)
    print("{ res:8 = val; export res; }")
