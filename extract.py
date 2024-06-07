#!/usr/bin/env python3
import argparse
import os
import re
import subprocess
import sys
import time

from inotify_simple import INotify, flags

deliver = '/usr/lib/dovecot/deliver'
blank_line = re.compile(r'^\s*$')
content_type = re.compile(r'^Content-Type: .+?; boundary="(.+?)"$')
message_id = re.compile(r'^Message-ID: <(.*)>$', re.I)
original_line = 'Content-Type: message/rfc822; x-spam-type=original'
sleep = 0


def _decode(line):
    try:
        return line.decode('utf-8')
    except UnicodeDecodeError:
        return line.decode('iso-8859-1')


def run_inotify(folder):
    inotify = INotify()
    watch_flags = flags.MOVED_TO
    wd = inotify.add_watch(folder, watch_flags)

    seen = []
    try:
        print('Watching %s for changes' % folder)
        while True:
            for event in inotify.read():
                base = event.name[:event.name.rindex(',')]
                if base not in seen:
                    seen.append(base)
                    path = os.path.join(folder, event.name)
                    if path.endswith('T'):
                        print('Ignoring message marked as deleted (%s)' % base)
                        continue
                    result = process_mail(path)
                    if result:
                        if sleep:
                            print('Got a spam mail, sleeping %d...' % sleep)
                            time.sleep(sleep)

                        with open(result, 'rb') as input:
                            retcode = subprocess.call([deliver], stdin=input)
                            print('Processed spam mail: %s - delivery: %s' % (path, retcode))
                        os.unlink(result)
    except KeyboardInterrupt:
        print()
        pass

    print('Finished watching %s' % folder)


def process_original(input, boundary_marker):
    boundary = re.compile('^--%s' % boundary_marker)

    output_name = os.path.join('/tmp', 'non-spam-msg-%s.eml' % time.time())
    with open(output_name, 'wb') as output:
        for line in input:
            line2 = line.decode('utf-8')
            if boundary.match(line2):
                break
            else:
                match =  message_id.match(line2)
                if match:
                    mid = match.group(1)
                    output.write(('Message-ID: <%s.%s.harris.ch>\r\n' % (mid, time.time())).encode('utf-8'))
                    output.write(('X-Original-Message-ID: <%s>\r\n' % mid).encode('utf-8'))
                else:
                    output.write(line)

    return output_name


def process_headers(input):
    is_spam = False
    boundary = None
    for line in input:
        line = _decode(line)

        # return only when the headers have been fully processed
        if blank_line.match(line):
            return is_spam, boundary

        if not is_spam and line.startswith('Subject: [SPAM]'):
            is_spam = True
        else:
            match = content_type.match(line)
            if match:
                boundary = match.group(1)


def process_mail(filename):
    with open(filename, 'rb') as input:
        is_spam, boundary_marker = process_headers(input)

        if is_spam:
            found_original = False
            for line in input:
                line = _decode(line)
                if line.startswith(original_line):
                    found_original = True
                    break

            if found_original:
                # skip remaining non-blank lines
                for line in input:
                    line = _decode(line)
                    if blank_line.match(line):
                        break

                return process_original(input, boundary_marker)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Utility for extracting original messages from SpamAssassin spam reports.')
    parser.add_argument('-s', '--sleep', type=int, help='Seconds to sleep before injecting extracted mail')
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('-f', '--file', help='The mail message file to process')
    actions.add_argument('-w', '--watch', help='Watch a directory for changes and process them')

    args = parser.parse_args()

    if args.sleep:
        sleep = args.sleep

    if args.file:
        if args.file.endswith('T'):
            sys.exit(1)

        print(process_mail(args.file))
    elif args.watch:
        run_inotify(args.watch)
    else:
        parser.print_help()
