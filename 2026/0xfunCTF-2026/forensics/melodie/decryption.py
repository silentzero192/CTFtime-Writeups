with open('extracted.bin', 'rb') as f:
    data = f.read()
idx = data.find(b'0xfun')
print(data[idx:idx+39])
