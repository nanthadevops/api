import json
import requests
import os
import pickle
import sys
requests.packages.urllib3.disable_warnings()

ts_authToken = "NULL"
if os.path.isfile("token.pickle"):
    ts_authToken = pickle.load(open("token.pickle", "rb"))

print("token details")
print(ts_authToken)

if len (sys.argv) == 4 :
    ts_hostname = sys.argv[1]
    ts_ipaddr = sys.argv[2]
    ts_msg = sys.argv [3]
#    print("values assigned")
#    print(ts_hostname)
#    print(ts_ipaddr)
#    print(ts_msg)
else:
    print(len (sys.argv) - 1)
    print("Expecting 3 command line arguments")
    sys.exit(1)

ts_body_getToken ={
       "username" : <user name>,
	   "password" : <password of the user>,
	   "tenantName" : "*"
	}

ts_body_getToken = json.dumps(ts_body_getToken)
ts_body_verifyToken = ts_body_getToken

ts_header_getToken = {
    'Content-Type': "application/json",
    'Accept': "application/json",
    'tenantId': "*"
      }

ts_headers_verifyToken = {
    'Content-Type': "application/json",
    'Accept': "application/json",
    'getTokenDetails': "True",
    'authToken': ts_authToken
	}

ts_header_postEvent = {
    'Content-Type': "application/json",
    'Authorization': "authToken "+ ts_authToken,
    }

ts_body_postEvent =[
    {
        "eventSourceHostName": ts_hostname,
        "eventSourceIPAddress": ts_ipaddr,
         "attributes": {
                "CLASS": "Event",
                "mc_object_uri": "",
                "severity": "WARNING",
                "msg": ts_msg,
                "mc_priority": "PRIORITY_4"
        }}
]

ts_body_postEvent = json.dumps(ts_body_postEvent)




def  getToken(header,body):
    # function to return token from TSPS
    print("Hello from a function")
    url_getToken = <API url to getTokent>
    body=body
    header=header
    response = requests.request("POST", url_getToken , data=body, headers=header,verify=False)
    response_json=json.loads(response.text)
    if response_json['statusMsg'] == "OK" and response_json['response']['status'] == "OK" :
        ts_authToken = response_json['response']['authToken']
        with open('token.pickle', 'wb') as f:
            pickle.dump(ts_authToken, f, pickle.HIGHEST_PROTOCOL)
        print(ts_authToken)
        return True
    else:
        print ("Invalid status Code")
        print(response.text)
        return False


def verifyToken(header,body):
    # verify token and returns True or False
    header=header
    body=body
    print("Hello from verifyToken")
    url_verify = <API URL for verify Token>
    response = requests.request("GET", url_verify, data=body, headers=header,verify=False)
    response_json = response.json()
    if response_json['statusMsg'] == "OK" :
        print("Token verified")
        return True
    else:
        getToken(ts_header_getToken,ts_body_getToken)


def postEvent(header,body):
    # post events to Truesight and return True or False
    print("inside postEvent")
    ts_header = header
    ts_body = body
    ts_url_postEvent = "<API URL to create event>
    querystring = {"routingId": <cell name>, "routingIdType": "CELL_NAME"}
    if ( verifyToken(ts_headers_verifyToken,ts_body_getToken) == True) :
        response = requests.request("POST",ts_url_postEvent,data=ts_body, headers=ts_header,params=querystring,verify=False)
        response_json = response.json()
        print(response_json['statusMsg'])
    else :
        print("Not a valid Token")
        sys.exit(1)

verifyToken(ts_headers_verifyToken,ts_body_getToken)
postEvent(ts_header_postEvent,ts_body_postEvent)
