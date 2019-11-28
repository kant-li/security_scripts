#! python3
#! -*- coding:utf8 -*-

"""
zip压缩或解压脚本，必要时可以使用字典或参数排列进行密码破解；

参数如下：
-f 需要解压的文件
-p 要使用的密码
-d 要使用的字典文件
-g 密码猜测的最大长度

用法示例：
python3 zipcracker.py -f myfile.zip
python3 zipcracker.py -f myfile.zip -p mypassword
python3 zipcracker.py -f myfile.zip -d mydictionary.txt
python3 zipcracker.py -f myfile.zip -g 8
"""

import argparse
import itertools
import os
import string
import sys
import zipfile


def _unzip(filepath, password=None, dictfile=None, maxlen=0):
    """解压缩文件"""
    try:
        zfile = zipfile.ZipFile(filepath)
    except (zipfile.BadZipFile, FileNotFoundError):
        sys.exit('Not a zipfile.')
    else:
        try:
            pwd = password.encode('ascii') if password is not None else None
            zfile.extractall(pwd=pwd)
        except Exception:
            if dictfile is not None:
                _unzip_with_dict(zfile, dictfile)
            if maxlen is not None and maxlen > 0:
                _unzip_with_guess(zfile, maxlen)
            msg = 'Need password.' if password is None else 'Wrong password.'
            sys.exit(msg)


def _unzip_with_dict(zfile, dictfile):
    """通过密码字典进行破解"""
    if not os.path.isfile(dictfile):
        sys.exit('Password dictionary not exist.')

    passfile = open(dictfile)
    for line in passfile.readlines():
        password = line.strip('\n')
        print('trying:' + password)
        try:
            zfile.extractall(pwd=password.encode('ascii'))
            sys.exit('password:' + password)
        except Exception:
            pass
    sys.exit('Password not in dictionary.')


def _unzip_with_guess(zfile, maxlen):
    """通过密码猜测进行破解"""
    for password in _password_generator(maxlen):
        print('trying:' + password)
        try:
            zfile.extractall(pwd=password.encode('ascii'))
            sys.exit('password:' + password)
        except Exception:
            pass
    sys.exit('Password guess failed.')


def _password_generator(maxlen):
    """密码生成器"""
    chars = string.printable
    for i in range(3, maxlen):
        for pwd in itertools.product(chars, repeat=i):
            yield ''.join(pwd)


def main():
    """主函数，读取命令行参数并进行处理"""
    parser = argparse.ArgumentParser(prog='zipcracker', description='Unzip zip files.')
    parser.add_argument('-f', '--file', type=str, help='zipfile path')
    parser.add_argument('-p', '--password', type=str, help='password for zipfile')
    parser.add_argument('-d', '--dict', type=str, help='code dictionary path')
    parser.add_argument('-g', '--guess', type=int, help='max length for guess')

    args = parser.parse_args()
    _unzip(filepath=args.file, password=args.password, dictfile=args.dict, maxlen=args.guess)


if __name__ == '__main__':
    main()
