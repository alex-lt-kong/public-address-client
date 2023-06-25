import random
import requests
import json
import os
import urllib3


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
    resp = requests.get(
        f'https://localhost:{settings["app"]["port"]}/?sound_name={sounds_list[random.randint(0, len(sounds_list)-1)]}',
        verify=False,
        auth=(settings["app"]["username"], settings["app"]["passwd"])
    )
    print(f'{i}/{max_sounds}: ', end='')
    print(resp.text)
