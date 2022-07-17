#!/usr/bin/python3
# -*- coding: utf-8 -*-

from emailer import emailer
from flask import Flask, Response, request
from waitress import serve

import argparse
import importlib
import json
import glob
import logging
import os
import signal
import subprocess
import sys
import threading
import time

app = Flask(__name__)
# app_dir: the app's real address on the filesystem
app_dir = os.path.dirname(os.path.realpath(__file__))
stop_signal = False
settings = {}
mpg123_process = None

playlist = []


# This function should be kept exactly the same among all
# public-address-servers/clients; otherwise, the same sound_index
# could result in different sound.
def get_song_by_id(sound_index: int):

    music_path = os.path.join(settings['app']['sound_repo_path'], 'custom-event/') + '*'
    songs_list = sorted(glob.glob(music_path), key=os.path.getsize)
    for song in songs_list:
        logging.debug(song)
    if songs_list is None or sound_index >= len(songs_list):
        return None, songs_list
    else:
        return songs_list[sound_index], songs_list


def playlist_handler():
    """
    Main loop thread used to handle incoming play request
    """

    global playlist, mpg123_process
    logging.info('playlist_handler "event loop" started')
    while stop_signal is False:

        time.sleep(0.05)
        if len(playlist) <= 0:
            continue

        logging.info('playlist: {}'.format(playlist))
        first_item = playlist.pop(0)

        if first_item[0] == 'custom':
            sound_index = first_item[1]
            mp3_path, sounds_list = get_song_by_id(sound_index)
            if mp3_path is None:
                logging.error('Unable to pick a sound.')
                continue

        if first_item[0] == 'chiming':
            mp3_name = 'cuckoo-clock-sound-0727.mp3'
            mp3_path = os.path.join(settings['app']['sound_repo_path'], mp3_name)

        mp3_name = os.path.basename(mp3_path)
        logging.info('Sound to be played: [{}]'.format(mp3_path))
        mpg123_process = subprocess.Popen(
                [settings['app']['mpg123_path'], '--no-control', '--utf8',
                 '--quiet', mp3_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
        out, err = mpg123_process.communicate()
        mpg123_process = None

        if len(out) > 0:
            logging.info('mpg123_process output: {}'.format(out.decode("utf-8")))
        if len(err) > 0:
            logging.error('mpg123_process error: {}'.format(err.decode("utf-8")))

        if len(playlist) == 0:
            logging.info('All items in playlist have been played or cleared')
    logging.info('playlist_handler "event loop" quited')


@app.route('/health_check/', methods=['GET'])
def health_check() -> Response:
    logging.info('health_check() fired, service is up and running!')
    return Response('Up and running/设备正常', 200)


@app.route('/clear_playlist/', methods=['GET'])
def clear_playlist():

    # user authentication is done by Apache config.
    global playlist, mpg123_process
    logging.info(f'clear_playlist command received. '
                 f'Existing playlist: {playlist}')

    while len(playlist) > 0:
        if playlist[-1][0] != 'chiming':
            last_item = playlist.pop()
            logging.info(f'{last_item} removed from the playlist')
        else:
            break

    if mpg123_process is not None:
        mpg123_process.kill()
        logging.info('mpg123_process kill command invoked')
    else:
        logging.info('mpg123_process is None, kill() method not invoked')

    logging.info(f'playlist cleared. Current playlist: {playlist}')

    return Response('playlist cleared', 200)


@app.route('/', methods=['GET'])
def index() -> Response:

    # user authentication is done by Apache config.
    notification_type = request.args.get('notification_type')
    if notification_type is None:
        return Response('Parameter missing (notification_type)', status=400)

    global playlist

    response_msg, sound_name = '', ''
    sound_index = -1

    if notification_type not in ['custom', 'chiming']:
        err_msg = 'Error: failed to match any conditions.'
        logging.error(err_msg)
        return Response(err_msg, status=400)

    if notification_type == 'custom':

        try:
            sound_index = int(request.args.get('sound_index'))
        except Exception as e:
            logging.exception('')
            return Response(str(e), status=400)
        if sound_index is None or sound_index < 0:
            err_msg = f'Invalid value (sound_index: {sound_index})'
            logging.error(err_msg)
            return Response(err_msg, status=400)

        playlist.append(['custom', sound_index])
        sound_name, songs_list = get_song_by_id(sound_index)
        if sound_name is None:
            err_msg = 'sound_index out of range'
            logging.error(err_msg)
            return Response(err_msg, status=400)
        sound_name = os.path.basename(sound_name)
        response_msg = (f'Success: {sound_name} (index={sound_index}) '
                        'added to the playlist')

    if notification_type == 'chiming':
        playlist.insert(0, ['chiming', -1])
        sound_name = 'chiming'
        response_msg = ('Success: chiming sound effect inserted to '
                        'the first place of the playlist')

    logging.info(f'new playback command received. notification_type: '
                 f'[{notification_type}], sound_index: [{sound_index}], '
                 f'sound_name: [{sound_name}], playlist: [{playlist}]')        

    return Response(response_msg, status=200)


def cleanup(*args) -> None:

    global stop_signal
    stop_signal = True
    logging.info('Stop signal received, exiting')
    sys.exit(0)


def main() -> None:

    ap = argparse.ArgumentParser()
    ap.add_argument('--debug', dest='debug', action='store_true')
    args = vars(ap.parse_args())
    debug_mode = args['debug']

    global settings
    with open(os.path.join(app_dir, 'settings.json'), 'r') as json_file:
        json_str = json_file.read()
        settings = json.loads(json_str)

    logging.basicConfig(
        filename=settings['app']['log_path'],
        level=logging.DEBUG if debug_mode else logging.INFO,
        format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - '
               '%(funcName)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    logging.info('public-address-client started')

    if debug_mode is True:
        print('Running in debug mode')
        logging.info('Running in debug mode')
        print(settings)
    else:
        logging.info('Running in production mode')

    if os.path.exists(settings['app']['mpg123_path']) is False:
        print(f"MP3 player {settings['app']['mpg123_path']} does not exist!")
        return

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    th_email = threading.Thread(target=emailer.send_service_start_notification,
                                kwargs={'settings_path': os.path.join(app_dir, 'settings.json'),
                                        'service_name': 'Public Address Client',
                                        'path_of_logs_to_send': settings['app']['log_path'],
                                        'delay': 0 if debug_mode else 300})
    th_email.start()

    playlist_handler_thread = threading.Thread(target=playlist_handler,
                                               args=())
    playlist_handler_thread.start()

    logging.info('Starting web server')

    serve(app, host="127.0.0.1", port=91)


if __name__ == '__main__':

    main()
