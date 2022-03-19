import pefile
import os

file_name=['sample_qwrty_dk2','sample_vg655_25th.exe']


for file in file_name:
	path = os.path.dirname(__file__)
	path = path + '/MALWR2/'
	pe = pefile.PE(path + file)

	for section in pe.sections:
		print('\n Seccion')
		print(section.Name, hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData)

	for entry in pe.DIRECTORY_ENTRY_IMPORT:
	    print('Llamadas DLL:')
	    print(entry.dll)
	    print('Llamadas a funciones:')
	    for function in entry.imports:
	    	print('\t', function.name)
	    	
	print('\n Header')  	
	print(pe.FILE_HEADER)
	
	print('\n Hash')
	print(pe.get_rich_header_hash('sha256'))

