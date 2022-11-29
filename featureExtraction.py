import json
from androguard.core.bytecodes.apk import APK

import os
import subprocess
import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt

Benign_DIR="/Users/anupkashyap/Downloads/Benign_2015"
Malware_DIR="/Users/anupkashyap/Downloads/Scareware"
apks = os.listdir(Benign_DIR)
count=0
app_features=[]
for apk in apks:
    count+=1
    try:
        print("Decoding app ("+ str(count)+"/"+str(len(apks))+")")
        a= APK(os.path.join(Benign_DIR,apk))
        features={}
        features["app_name"]=a.get_app_name()
        features["permissions"]=a.get_permissions()
        features["libraries"]=a.get_libraries()
        features["activities"]=a.get_activities()
        #features["certificates"]=a.get_certificates()
        features["files"]=a.get_files()
        features["features"]=a.get_features()
        features["providers"]=a.get_providers()
        features["minSDKVersion"]=a.get_min_sdk_version()
        features["maxSDKVersion"]=a.get_max_sdk_version()
        features["receivers"]=a.get_receivers()
        features["services"]=a.get_services()
        features["isSigned"]=a.is_signed()
        features["isMalicious"] = False
        #print(a.get_permissions())
        app_features.append(features)
    except Exception as e:
        print(e)
        pass

with open("newFeaturesBenign.json",'w') as f:
    f.write(json.dumps(app_features))


apks = os.listdir(Malware_DIR)
count=0
app_features=[]
for apk in apks:
    count+=1
    try:
        print("Decoding app ("+ str(count)+"/"+str(len(apks))+")")
        a= APK(os.path.join(Malware_DIR,apk))
        features={}
        features["app_name"]=a.get_app_name()
        features["permissions"]=a.get_permissions()
        features["libraries"]=a.get_libraries()
        features["activities"]=a.get_activities()
        #features["certificates"]=a.get_certificates()
        features["files"]=a.get_files()
        features["features"]=a.get_features()
        features["providers"]=a.get_providers()
        features["minSDKVersion"]=a.get_min_sdk_version()
        features["maxSDKVersion"]=a.get_max_sdk_version()
        features["receivers"]=a.get_receivers()
        features["services"]=a.get_services()
        features["isSigned"]=a.is_signed()
        features["isMalicious"] = True
        #print(a.get_permissions())
        app_features.append(features)
    except Exception as e:
        print(e)
        pass

with open("newFeaturesMalware.json",'w') as f:
    f.write(json.dumps(app_features))

