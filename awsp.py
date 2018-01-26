#!/usr/bin/env python3

import os
import configparser
from pathlib import Path
import boto3
import getpass
import sys

def load_config(path='~/.aws/config'):
    parser = configparser.ConfigParser()
    f = Path(path).expanduser().resolve()
    assert f.is_file()
    parser.read(f)
    return parser

def section_name(profile):
    return f'profile {profile}'

def get_token_code():
    return getpass.getpass('Enter your MFA token: ')

def get_session_token(session, mfa_serial):
    token_code = get_token_code()
    res = session.client('sts').get_session_token(
        SerialNumber=mfa_serial,
        TokenCode=token_code
        )
    return res['Credentials']

def to_env(creds):
    return {
        'AWS_ACCESS_KEY_ID':     creds['AccessKeyId'],
        'AWS_SECRET_ACCESS_KEY': creds['SecretAccessKey'],
        'AWS_SESSION_TOKEN':     creds['SessionToken'],
        }

def get_profile_env(config, profile):
    section = config[section_name(profile)]

    ret = {'AWS_PROFILE': profile}

    if 'source_profile' in section:
        assert 'role_arn' in section

        print('Using source profile `{}`'.format(section['source_profile']))
        source_section = config[section_name(section['source_profile'])]
        session = boto3.Session(profile_name=section['source_profile'])

        if 'mfa_serial' in source_section:
            ret.update(to_env(get_session_token(session, source_section['mfa_serial'])))

        else:
            print('I don\'t know how this works yet b/c you would never get the temp creds from the source profile')
            sys.exit(1)

        # NOTE: we don't do an sts.assume_role here b/c then we have to wait for two tokens
        #       and the regular aws cli does a pretty good job of

    elif 'mfa_serial' in section:
        session = boto3.Session(profile_name=profile)
        ret.update(to_env(get_session_token(session, section['mfa_serial'])))

    return ret

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('profile')
    parser.add_argument('rest', nargs='*', default=('bash', '--noprofile'))
    args = parser.parse_args()

    config = load_config()

    env = os.environ.copy()
    env['AWS_PROFILE'] = args.profile

    creds = get_profile_env(config, args.profile)
    env.update()

    os.execvpe(args.rest[0], args.rest, env)
