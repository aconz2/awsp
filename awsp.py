#!/usr/bin/env python3

import os
import configparser
from pathlib import Path
import boto3
import getpass
import sys
from datetime import datetime

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

def assume_role(session, role, mfa_serial=None):
    rest = {}
    if mfa_serial:
        token_code = get_token_code()
        rest.update(
            SerialNumber=mfa_serial,
            TokenCode=token_code,
            )
    res = session.client('sts').assume_role(
        RoleArn=role,
        RoleSessionName='{}-{}'.format(os.environ['USER'], datetime.utcnow().timestamp()),
        **rest
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
        session = boto3.Session(profile_name=section['source_profile'])

        # TODO: if source_profile mfa_serial is different than current profile, do we have to do
        #       a get_session_token then an assume role??
        ret.update(to_env(assume_role(session, section['role_arn'], section.get('mfa_serial'))))

    elif 'mfa_serial' in section:
        session = boto3.Session(profile_name=profile)
        ret.update(to_env(get_session_token(session, section['mfa_serial'])))

    return ret

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('profile')
    parser.add_argument('rest', nargs='*', default=('bash', '--noprofile'))
    args = parser.parse_args()

    config = load_config(os.getenv('AWS_CONFIG_FILE', '~/.aws/config'))

    env = os.environ.copy()
    env['AWS_PROFILE'] = args.profile

    env.update(get_profile_env(config, args.profile))

    os.execvpe(args.rest[0], args.rest, env)

if __name__ == '__main__':
    main()
