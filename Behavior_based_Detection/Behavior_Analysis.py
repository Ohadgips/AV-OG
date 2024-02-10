import os,requests
import json

# use sandbox to analyze file behavior:
API_URL = "http://your_cape_server_ip:8000"

# choose a file to test
def file_for_analysis(file_path):
    
    headers = {"Content-Type": "application/json"}
   
    data = {
    "file": open(file_path, "rb").read().encode("base64"),
        "config": {
            "analysis_target": "file",
            "target": "http",
            "advanced": {}
            }
    }
    
    # Submit file for analysis
    response = requests.post(f"{API_URL}/analyze", headers=headers, data=json.dumps(data))

    analysis_id = response.json().get("id")

    return analysis_id


# Get cuckoo sandbox analysis result
def get_result(analysis_id):

    response = requests.get(f"{API_URL}/analysis/{analysis_id}/json")
    
    analysis_results = response.json()
    
    return analysis_results.json()


if __name__ == "__main__":

    # give file path
    file_path = ""

    # Start analysis
    analysis_id = file_for_analysis(file_path)
    print ("ID: ",analysis_id)


    # Get result
    results = get_result(analysis_id)
    print("Analysis Results:", results)
    json_file = open('analysis_data.json', 'w')
    json.dump(results, json_file)
