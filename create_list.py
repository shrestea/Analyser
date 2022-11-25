import os
import hashlib
import json
import subprocess
import timeit

malwareDir = 'Virus/'
def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

arr = os.listdir('Virus')

num_files=len(arr)
print("Number of files: "+str(num_files))

print("Batch processing started")
i=0
count=0
query_array=[]
start = timeit.default_timer()

for i in range(1, 10):
    i+=1 
    count+=1
    query={}
    file = arr[i]
    # Full path
    filename=malwareDir+file

    if str(os.popen('readelf -h '+filename).read()).find("ELF")>=0:
	    # MD5    
	    # query+=(str(md5(filename)),)
        md5_name = str(md5(filename))
        query['md5'] = md5_name

	    # Peframe
	    # tmp_peframe=os.popen('peframe -j '+filename).read()
        tmp_peframe = str(os.popen('peframe -j '+filename).read())
        query['peframe'] = md5

	    # Readelf
	    # query+=(str(os.popen('readelf -h '+filename).read()),)
        elf= str(os.popen('readelf -h '+filename).read())
        query['elf'] = elf
	    
	    # 'file' command
	    # query+=(str(os.popen('file -b '+filename).read()),)
        file_q = str(os.popen('file -b '+filename).read())
        query['file']= file_q
	    
	    # 'strings' command
	    # query+=(str(os.popen('strings '+filename).read()),)
        strings = str(os.popen('strings '+filename).read())
        query['strings'] = str(os.popen('strings '+filename).read())

	    # filesize
	    # query+=(str(os.path.getsize(filename)),)
        filesize = str(os.path.getsize(filename))
        query['filesize'] = filesize
	    
	    # Shannon Entropy  - ent tool
        entropy = str(os.popen("ent "+filename+" | head -n 1 |  awk '{print $(NF-3)}'").read())
	    # entropy = str(os.popen("ent "+filename+" | head -n 1 |  awk '{print $(NF-3)}'").read().strip())
        query['entropy'] = entropy
	    
	    # # md5 on duplicate
	    # query+=(str(md5(filename)),)
	    
	    # # peframe on duplicate
	    # query+=tmp_peframe
        query_array.append(query)
f = open("dataset.txt", "w")
f.write(query_array)
f.close()