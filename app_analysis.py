import pprint
APPS_ORG_MAP = {'Icloud': 'icloud',
        'Weibo': 'sina',
        'Google': 'google',
        'Taobao': 'taobao',
        'Adobe' : 'adobe',
        'Facebook': 'facebook',
        'Amazon': 'amazon',
        'Yahoo!': 'yahoo',
        'Akamai' : 'akamai',
        'Apple' : 'apple',
        'TencentQQ': 'tencent',
        'GitHub': 'github',
        'Twitter': 'twitter'}

apps_count = {}

for key in APPS_ORG_MAP.keys():
    tmp = 0
    with open("result.txt", "r") as lines:
        for line in lines:
            if APPS_ORG_MAP[key].lower() in line.lower():
                line = line.split(' ')
                print (key + "has" + line[2])
                tmp += int(line[2])
    apps_count[key] = tmp
                
pprint.pprint(apps_count)
