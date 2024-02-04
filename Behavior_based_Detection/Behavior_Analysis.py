import os,requests
import json

# use sandbox to analyze file behavior:
API_URL = "https://localhost:8090/cuckoo/api"

# choose a file to test
def choose_file(file_path):
    files = {"file":open(file_path,'rb')}

    response = requests.post(f"{API_URL}/tasks/create/file",files=files)
    
    task_id = response.json.get('task_id')

    return task_id

# Get cuckoo sandbox analysis result
def get_result(task_id):

    response = requests.get(f"{API_URL}/tasks/report/{task_id}")
    return response.json()


if __name__ == "__main__":

    # give file path
    file_path = ""

    # Start analysis
    task_id = choose_file(file_path)
    print ("ID: ",task_id)


    # Get result
    results = get_result(task_id)
    json_file = open('analysis_data.json', 'w')
    json.dump(results, json_file)
    print("results: ", results)

    # For Python 2.7
    import io, json
    with io.open('data.txt', 'w', encoding='utf-8') as f:
        f.write(json.dumps(results, ensure_ascii=False))
