import json

cache_file_path = "cached_data.json"
data = []

RECORDS_DATA_LIMIT = 100
PCENT_RECORDS_DROP_WHEN_FULL = 20

def drop_old_records():
    sorted_items = sorted(data.items(), key=lambda item: item[1][0])
    num_items_to_keep = int( len(sorted_items) * ((float)(100-PCENT_RECORDS_DROP_WHEN_FULL) / (float)(100.0)) )
    items_to_keep = sorted_items[:num_items_to_keep]
    data = dict(items_to_keep)

def data_write(key,value):
    if(len(data)>=RECORDS_DATA_LIMIT):
        print(f"{RED}Cache data records full. Will drop {PCENT_RECORDS_DROP_WHEN_FULL}% of cached records to make room for new ones{RESET}")
        drop_old_records()
    data[key] = [ time.time() , value ]

def data_record_retrieve(key):
    if key not in data:
        return None
    data[key][0] = time.time()
    return data[key][1]

def data_loading():
    with open(cache_file_path,"r") as file:
        data = json.load(file)

def data_saving():
    with open(cache_file_path,"w") as file:
        json.dump(data,file)
