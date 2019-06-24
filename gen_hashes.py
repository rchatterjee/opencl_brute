import sys
from Library import opencl
from Library.opencl_information import opencl_information
from binascii import unhexlify, hexlify
from collections import deque
from hashlib import pbkdf2_hmac, sha256
from itertools import islice, tee, chain

N = 1024 * 1024 * 4
LIM_LEN = 119

def iter_in_chunk(it, size=1, skip=0):
    """ Iterate @it in chunks of size @chun_size"""
    if skip>0:
        print("Skipping first {} lines".format(skip))
    sourceiter = iter(islice(it, skip, None))
    print(list(islice(sourceiter, 1)))
    while True:
        batchiter = islice(sourceiter, size)
        yield chain([next(batchiter)], batchiter)

def sha256_test(opencl_algo, passwf, skiplines=0, clean=lambda x: x):
    print("Testing sha256 ..")
    ctx=opencl_algo.cl_sha256_init()
    done = 0
    outfname = "outfile.txt"
    with open(passwf, 'rb') as pwf, open(outfname, 'wb') as outf:
        for lines_it in iter_in_chunk(pwf, size=N, skip=skiplines):
            lines = list(lines_it)
            # Remove large strings
            passwordlist = [clean(l.split()[-1]) for l in lines]
            ipws = {i for i, l in enumerate(passwordlist) if len(l) > (LIM_LEN)}
            for i in ipws:
                passwordlist[i] = passwordlist[i][-LIM_LEN:]

            clresult=opencl_algo.cl_sha256(ctx, passwordlist)
            for i in ipws:
                clresult[i] = sha256(lines[i].split()[-1]).digest()

            done += len(clresult)
            print("Done {} lines".format(done))
            outf.write(b'\n'.join(
                # b"{}\t{}".format(l, hexlify(x))
                clean(l) + b"\t" + hexlify(x)
                for l,x in zip(lines, clresult)
            ))
            outf.write(b'\n')
            if len(passwordlist) < N-1:
                break

def _get_pws(lines):
    for l in lines:
        yield l.rstrip().split()[-1][-LIM_LEN:]

def hashval(l, h):
    pw = l.rstrip().split()[-1]
    if len(pw) > LIM_LEN:
        return hexlify(sha256(lines[i].split()[-1].encode('utf-8')).digest())
    else:
        return h

def get_sha256_hashes(opencl_algo, passwf):
    raise ValueError("Does not work! Takes terrabytes of RAM")
    ctx=opencl_algo.cl_sha256_init()
    with open(passwf, 'rb') as pwf, open('outf.txt', 'wb'):
        orig_pwf, pwf = tee(pwf)
        pws = _get_pws(pwf)
        clresult=opencl_algo.cl_sha256(ctx, pws)
        for l, r in zip(orig_pwf, clresult):
            print("{}\t{}".format(l, hashval(l, r)))


def test_sha256(opencl_algo, pws):
    ctx=opencl_algo.cl_sha256_init()
    clresult=opencl_algo.cl_sha256(ctx, pws)
    print('\n'.join(
        "{}\t{}".format(l, hexlify(x).decode('utf-8'))
        for l,x in zip(pws, clresult)
    ))
    
    

if __name__ == "__main__":
    if (len(sys.argv)<3):
        print("Implementation tests")
        print("-----------------------------------------------------------------")
        info=opencl_information()
        info.printplatforms()
        print("\nPlease run as: python {} [platform number] [input filename]".format(sys.argv[0]))
        exit(0)

    platform = int(sys.argv[1])
    inpf = sys.argv[2]
    debug = 0
    write_combined_file = False
    opencl_algos = opencl.opencl_algos(platform, debug, write_combined_file, inv_memory_density=1)
    sha256_test(opencl_algos, inpf, skiplines=0, clean=lambda x: x.lower())
    # get_sha256_hashes(opencl_algos, inpf)
    # test_sha256(opencl_algos, [b"7349h3i2865g5b35ioi7sekiow8edrfd89sw8i3e837837u3e7uj4rde7e37yuhe3wu8j3w2e8i3e7ujyhe7yuhjn3e7u4deu8jm4re8u48uijw3ej83w2e8iw3e7u4re74red78w3e8uie3ws8e4u8i7u4eu8i3e93e8iur47uiedj4r57u4re4re747ur4r7u4r7u4r7u7ru74r4r74r7e4er7ej7un6to2g7378ot5t7oir@zoomtown.co"[-119:], b"a@b.com"])

