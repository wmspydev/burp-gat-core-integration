import requests

url = "https://homolog.gat.digital/app/vulnerability/upload/api/Burp"

payload = {}
files = [
  ('file', open('D:/GAT Digital/Works/burp-extension/src/exports/9ff05acdbd3143dbba2dfb0b36835057.csv','rb'))
]
headers = {
  'Authorization': 'Bearer 1f55c9ef-974a-4182-8361-1190cef3bef8',
  'Content-Type': 'multipart/form-data',
  'Accept': 'application/json'
}

response = requests.request("POST", url, headers=headers, data = payload, files = files)

print(response.text.encode('utf8'))
