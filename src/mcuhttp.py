#!/usr/bin/python
# coding=utf-8

# Copyright (c) 2019, Zheng Zhaocong. All rights reserved.
#
# This file is part of mcuhttp.
# 
# mcuhttp is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as 
# published by the Free Software Foundation, either version 3 of
# the License, or (at your option) any later version.
# 
# mcuhttp is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with mcuhttp.  If not, see <https://www.gnu.org/licenses/>.

import os, sys
import re
import gzip
import argparse
import StringIO
import hashlib
import mimetypes

ROUTER_TEMPLATE = """
    { \\
        .path = "%s", \\
        .type = MCUHTTP_ROUTER_%s, \\
        .data = { \\
            .mime = "%s", \\
            .data = %s, \\
            .data_len = %s_len, \\
        } \\
    }
"""

mimetypes.init()

def main():
	parser = argparse.ArgumentParser(description='Convert file to c header.', epilog='thinhttp 2.1')
	parser.add_argument('-g', action='store_true', help='uese gzip')
	parser.add_argument('-w', action='store_true', help='write gz file')
	parser.add_argument('-c', action='store_true', help='write to stdin')
	parser.add_argument('-r', action='store_true', help='generate router')
	parser.add_argument('-v', action='store_true', help='verbose')
	parser.add_argument('-b', type=str, default='/', help='base path of router. default \'/\'')
	parser.add_argument('-p', type=str, default='MCUHTTP_', help='macro prefix. default \'THINHTTP_\'')
	parser.add_argument('-o', metavar='output file', type=str, nargs=1, help='write to file')
	parser.add_argument('file', type=str,nargs='+', help='input file')
	args = parser.parse_args();

	if args.o:
		out_file = open(args.o[0], 'wb')
	else:
		out_file = None

	size_sum = 0

	for in_file_name in args.file:

		file_basename = os.path.basename(in_file_name)
		file_name = re.match('(.*?)(\\.[^.]*|.{0})$', file_basename).group(1)
		array_name = file_basename.replace('.', '_').replace('-', '_')
		header_name = file_name + '.h'
		file_mime = mimetypes.guess_type(file_basename)[0]
		if file_mime is None:
			file_mime = 'text/plain'

		if os.path.basename(in_file_name) == header_name:
			header_name += '_'

		with open(in_file_name, 'rb') as fp:
			raw_data = fp.read()

		origion_size = len(raw_data)

		md5 = hashlib.md5(raw_data).hexdigest()

		if args.g:
			sio = StringIO.StringIO()
			gf = gzip.GzipFile(mode='w', compresslevel=9, fileobj=sio)
			gf.write(raw_data);
			gf.close()

			raw_data = sio.getvalue()
			array_name += '_gzip'

			if args.w:
				with open(file_name + '.gz', 'wb') as fp:
					fp.write(raw_data)

		size_sum += len(raw_data)

		header =  '// %s\n' % file_basename
		header += '// MD5: %s\n' % md5
		if args.g and origion_size > 0:
			header += '// Size: %d (%.2f)\n' % (len(raw_data), len(raw_data)/float(origion_size))
		else:
			header += '// Size: %d\n' % len(raw_data) 

		if args.r:
			router_name = '%sROUTER_%s' % \
				(args.p, os.path.basename(in_file_name).replace('.', '_').replace('-', '_').upper())

			if not args.c:
				print(router_name)

			header += '#define %s \\' % router_name
				
			header += ROUTER_TEMPLATE % (
				os.path.join(args.b, file_basename),
				'GZIP' if args.g else 'FILE',
				file_mime, 
				array_name,
				array_name)
			
		header += '#define %s_len %d\n' % (array_name, len(raw_data))
		header += 'const char %s[] = {\n' % array_name

		ii = 0
		for c in raw_data:
			header += '0x%.2x,' % (ord(c))
			ii += 1
			if ii % 15 == 0:
				header += '\n'

		header += '};\n'

		if args.c:
			print(header)
		else:
			if out_file:
				out_file.write(header)
			else:
				with open(header_name, 'wb') as fp:
					fp.write(header)
	if out_file:
		out_file.write("//Total: %d\n" % size_sum)
		out_file.close()

if __name__ == '__main__':
	main()
