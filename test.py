#!/usr/bin/python3
# -*- coding: utf-8 -*-
import sys
import hashlib
import hmac
import scrypt
import functools, operator
from Library import opencl
from Library.opencl_information import opencl_information
from binascii import unhexlify, hexlify
from hashlib import pbkdf2_hmac

# ===================================== Test funcs =============================================

def test(hashClass, passwordlist, clresult):
    # Generate the correct results using hashlib
    correct_res = []
    for pwd in passwordlist:
        h = hashClass()
        h.update(pwd)
        correct_res.append(h.digest())

    # Determine success and print
    correct = [r==c for r,c in zip(clresult, correct_res)]
    succ = (len(passwordlist) == len(clresult)) and functools.reduce(operator.and_, correct, True)
    if succ:
        print ("Ok m8!")
    else:
        print ("Failed !")
        print(clresult[0])
        print(correct_res[0])

def sha256_test(opencl_algo, passwordlist):
    print("Testing sha256 ..")
    ctx=opencl_algo.cl_sha256_init()
    clresult=opencl_algo.cl_sha256(ctx,passwordlist)
    test(hashlib.sha256, passwordlist, clresult)

def md5_test(opencl_algo, passwordlist):
    print("Testing md5 ..")
    ctx=opencl_algo.cl_md5_init()
    clresult=opencl_algo.cl_md5(ctx,passwordlist)
    test(hashlib.md5, passwordlist, clresult)

def sha1_test(opencl_algo, passwordlist):
    print("Testing sha1 ..")
    ctx=opencl_algo.cl_sha1_init()
    clresult=opencl_algo.cl_sha1(ctx,passwordlist)
    test(hashlib.sha1, passwordlist, clresult)

def hmac_test(passwordlist, salt, hashClass, clResult):
    correct_res = []
    for pwd in passwordlist:
        correct_res.append(hmac.new(pwd, salt, hashClass).digest())

    # Determine success and print
    correct = [r == c for r, c in zip(clResult, correct_res)]
    succ = (len(passwordlist) == len(clResult)) and functools.reduce(operator.and_, correct, True)
    if succ:
        print("Ok m9!")
    else:
        print("Failed !")
        print(clResult[0])
        print(correct_res[0])


def md5_hmac_test(opencl_algo, passwordlist, salt):
    print("Testing hmac using md5.cl")
    ctx=opencl_algo.cl_md5_init("pbkdf2.cl")
    clResult=opencl_algo.cl_md5_hmac(ctx,passwordlist,salt)
    hmac_test(passwordlist, salt, hashlib.md5, clResult)

def sha256_hmac_test(opencl_algo, passwordlist, salt):
    print("Testing hmac using sha256.cl")
    ctx=opencl_algo.cl_sha256_init("pbkdf2.cl")
    clResult=opencl_algo.cl_sha256_hmac(ctx,passwordlist,salt)
    hmac_test(passwordlist, salt, hashlib.sha256, clResult)

def sha1_hmac_test(opencl_algo, passwordlist, salt):
    print("Testing hmac using sha1.cl")
    ctx=opencl_algo.cl_sha1_init("pbkdf2.cl")
    clResult=opencl_algo.cl_sha1_hmac(ctx,passwordlist,salt)
    hmac_test(passwordlist, salt, hashlib.sha1, clResult)

def pbkdf2_test(passwordlist, salt, hashName, iters, dklen, clResult):
    correct_res = []
    for pwd in passwordlist:
        correct_res.append(hashlib.pbkdf2_hmac(hashName, pwd, salt, iters, dklen))

    # Determine success and print
    correct = [r == c for r, c in zip(clResult, correct_res)]
    succ = (len(passwordlist) == len(clResult)) and functools.reduce(operator.and_, correct, True)
    if succ:
        print("Ok m10!")
    else:
        print("Failed !")
        for i in range(len(passwordlist)):
            if clResult[i] == correct_res[i]:
                print("#{} succeeded".format(i))
            else:
                print(i)
                print(clResult[i])
                print(correct_res[i])

def pbkdf2_hmac_md5_test(opencl_algo, passwordlist, salt, iters, dklen):
    print("Testing pbkdf2-hmac using md5.cl")
    ctx=opencl_algo.cl_pbkdf2_init("md5",len(salt),dklen)
    clResult = opencl_algo.cl_pbkdf2(ctx,passwordlist, salt, iters, dklen)
    pbkdf2_test(passwordlist, salt, "md5", iters, dklen, clResult)

def pbkdf2_hmac_sha1_test(opencl_algo, passwordlist, salt, iters, dklen):
    print("Testing pbkdf2-hmac using sha1.cl")
    ctx=opencl_algo.cl_pbkdf2_init("sha1", len(salt), dklen)
    clResult = opencl_algo.cl_pbkdf2(ctx,passwordlist, salt, iters, dklen)
    pbkdf2_test(passwordlist, salt, "sha1", iters, dklen, clResult)

def pbkdf2_hmac_sha256_test(opencl_algo, passwordlist, salt, iters, dklen):
    print("Testing pbkdf2-hmac using sha256.cl")
    ctx=opencl_algo.cl_pbkdf2_init("sha256", len(salt), dklen)
    clResult = opencl_algo.cl_pbkdf2(ctx,passwordlist, salt, iters, dklen)
    pbkdf2_test(passwordlist, salt, "sha256", iters, dklen, clResult)

def scrypt_test(scrypt_opencl_algos, passwords, N_value=15, r_value=3, p_value=1, desired_key_length=32,
                hex_salt=unhexlify("DEADBEEFDEADBEEFDEADBEEFDEADBEEF")):
    print("Testing scrypt")
    correct_res = []
    for pwd in passwords:
        v = scrypt.hash(pwd, hex_salt, 1 << N_value, 1 << r_value, 1 << p_value, desired_key_length)
        correct_res.append(v)
    ctx=scrypt_opencl_algos.cl_scrypt_init(N_value)
    clResult = scrypt_opencl_algos.cl_scrypt(ctx,passwords,N_value,r_value,p_value,desired_key_length,hex_salt)

    # Determine success and print
    correct = [r == c for r, c in zip(clResult, correct_res)]
    succ = (len(passwords) == len(clResult)) and functools.reduce(operator.and_, correct, True)
    if succ:
        print("Ok m11!")
    else:
        print("Failed !")
        for i in range(len(passwords)):
            if clResult[i] == correct_res[i]:
                print("#{} succeeded".format(i))
            else:
                print(i)
                print(clResult[i])
                print(correct_res[i])

# ===========================================================================================

def main(argv):
    if (len(argv)<2):
        print("Implementation tests")
        print("-----------------------------------------------------------------")
        info=opencl_information()
        info.printplatforms()
        print("\nPlease run as: python test.py [platform number]")
        return

    # Input values to be hashed
    passwordlist = [b'password', b'hmm', b'trolololl', b'madness']
    salt = b"salty"
    
    platform = int(argv[1])
    debug = 0
    write_combined_file = False
    opencl_algos = opencl.opencl_algos(platform, debug, write_combined_file,inv_memory_density=1)
    # Call the tests

    md5_test(opencl_algos,passwordlist)
    sha256_test(opencl_algos,passwordlist)
    sha1_test(opencl_algos,passwordlist)

    md5_hmac_test(opencl_algos, passwordlist, salt)
    sha1_hmac_test(opencl_algos, passwordlist, salt)
    sha256_hmac_test(opencl_algos, passwordlist, salt)
    
    pbkdf2_hmac_md5_test(opencl_algos, passwordlist, salt, 1000, 50)
    pbkdf2_hmac_sha1_test(opencl_algos, passwordlist, salt, 1000, 50)
    pbkdf2_hmac_sha256_test(opencl_algos, passwordlist, salt, 1000, 50)
    
    scrypt_test(opencl_algos,passwordlist,15,3,1,0x20,salt)

    print("Tests have finished.")

if __name__ == '__main__':
  main(sys.argv)
