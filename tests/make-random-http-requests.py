import random
import requests
import json
import os
import urllib3
import string


curr_dir = os.path.dirname(os.path.realpath(__file__))
max_sounds = 4096

settings = None
with open(os.path.join(curr_dir, '..', 'settings.json')) as f:
    # Load the JSON data into a Python object
    settings = json.load(f)
# print(settings)

sounds_list = [
    'minuet-in-g-major_bach_fade-in.mp3',
    'salut-damor_爱的问候_edward-elgar_normalized.mp3',
    'a-comme-amour_richard-clayderman_fade-in_normalized.mp3',
    'flat-major-op6-no7-hwv325_george-frideric-handel_fade-in_normalized.mp3',
    'non-existent-sound.mp3',
    '0-cuckoo-clock-sound.mp3',
    '0-cuckoo-clock-sound.mp3',
    '0-cuckoo-clock-sound.mp3',
    '0-cuckoo-clock-sound.mp3',
    '0-cuckoo-clock-sound.mp3'
]

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
for i in range(max_sounds):
    length = random.randint(0, 4096)

    username = ''.join(random.choices(
        string.ascii_lowercase + string.digits, k=length))
    if random.randint(0, 2) == 0:
        username = settings["app"]["username"]
    password = ''.join(random.choices(
        string.ascii_lowercase + string.digits, k=length))
    if random.randint(0, 2) == 0:
        password = settings["app"]["passwd"]

    url = f'https://{username}:{password}@localhost:{settings["app"]["port"]}/'
    if random.randint(0, 4) == 0:
        url += f'?sound_name={sounds_list[random.randint(0, len(sounds_list)-1)]}'
    else:
        url += ''.join(random.choices(
            string.ascii_lowercase + string.digits, k=length))

    print(f'{i}/{max_sounds} ({url[:64]}): ', end='')
    resp = requests.get(url, verify=False)
    print(f'{resp.status_code}: {resp.text}')
