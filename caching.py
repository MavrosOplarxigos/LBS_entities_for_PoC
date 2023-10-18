import json
import os
from colorama import init, Fore
from debug_colors import *
import threading
import time
import base64

cache_file_path = "cached_data.json"
data = {}
mock_json = { "record1": [ 12312 , "Data1" ], } 
MUTEX_DATA_WRITING_LOCK = threading.Lock()
MUTEX_JSON_DATA_FILE_ACCESS_LOCK = threading.Lock()

RECORDS_DATA_LIMIT = 100
PCENT_RECORDS_DROP_WHEN_FULL = 20

# This function is called only by data_write which already locks the MUTEX_DATA_WRITING_LOCK
def drop_old_records():
    global MUTEX_JSON_DATA_FILE_ACCESS_LOCK
    with MUTEX_JSON_DATA_FILE_ACCESS_LOCK:
        global data
        sorted_items = sorted(data.items(), key=lambda item: item[1][0])
        num_items_to_keep = int( len(sorted_items) * ((float)(100-PCENT_RECORDS_DROP_WHEN_FULL) / (float)(100.0)) )
        items_to_keep = sorted_items[:num_items_to_keep]
        data = dict(items_to_keep)

def serial_encoder(value):
    return base64.b64encode(value).decode('utf-8')

def serial_decoder(value):
    return base64.b64decode(value.encode('utf-8'))

def data_write(key,value):
    global MUTEX_DATA_WRITING_LOCK
    with MUTEX_DATA_WRITING_LOCK:
        global data
        if( len(data) >= RECORDS_DATA_LIMIT):
            print(f"{RED}Cache data records full. Will drop {PCENT_RECORDS_DROP_WHEN_FULL}% of cached records to make room for new ones{RESET}")
            drop_old_records()
        data[key] = [ time.time() , serial_encoder(value) ]

def data_record_retrieve(key):
    global MUTEX_DATA_WRITING_LOCK
    with MUTEX_DATA_WRITING_LOCK:
        if key not in data:
            return None
        data[key][0] = time.time()
        return serial_decoder(data[key][1])

def exists_data_file():
    try:
        with open(cache_file_path,"rb") as file:
            return True
    except Exception as e:
        return False

def create_data_file():
    global MUTEX_JSON_DATA_FILE_ACCESS_LOCK
    with MUTEX_JSON_DATA_FILE_ACCESS_LOCK:
        try:
            with open(cache_file_path,"w") as file:
                json.dump(mock_json, file,indent=4)
        except Exception as e:
            print(f"{RED}Error on writing the file: {e}{RESET}")

def data_loading():
    global MUTEX_DATA_WRITING_LOCK
    with MUTEX_DATA_WRITING_LOCK:
        global MUTEX_JSON_DATA_FILE_ACCESS_LOCK
        with MUTEX_JSON_DATA_FILE_ACCESS_LOCK:
            try:
                global data
                if not exists_data_file():
                    print(f"{RED}The file doesn't exist and thus we will create it.{RESET}")
                    create_data_file()
                else:
                    pass
                    # print(f"{GREEN}The file does exist!{RESET}")
                # check if the file exists first
                with open(cache_file_path,"r") as file:
                    data = {}
                    file_contents = file.read()
                    # print(f"The file contents are: {file_contents}",flush=True)
                    data = json.loads(file_contents)
                    return True
                    print(f"{GREEN}The JSON data are loaded!{RESET}",flush=True)
            except Exception as e:
                print(f"{RED}Data loading error: {e}{RESET}")
                return False

def data_saving():
    global MUTEX_JSON_DATA_FILE_ACCESS_LOCK
    with MUTEX_JSON_DATA_FILE_ACCESS_LOCK:
        global data
        with open(cache_file_path,"w") as file:
            json.dump(data,file,indent=4)

def main():
    colorama_init()
    result = data_loading()
    if not result:
        return
    print(f"Data is:\n{data}",flush=True)
    try:
        data_saving()
        print(f"{GREEN}The data dictionary was saved in the file!{RESET}")
    except Exception as e:
        print("Error on saving:",e)
    return

if __name__ == "__main__":
    main()
