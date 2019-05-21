#!/usr/bin/env python3

import os
import configparser
from pathlib import Path
import boto3
import getpass
import sys
from datetime import datetime

def load_config(path):
    parser = configparser.ConfigParser()
    f = Path(path).expanduser().resolve()
    assert f.is_file()
    parser.read(f)
    return parser

def section_name(profile):
    return f'profile {profile}'

def get_token_code():
    return getpass.getpass('Enter your MFA token: ')

def get_session_token(session, mfa_serial, mfa_code=None):
    token_code = mfa_code or get_token_code()
    res = session.client('sts').get_session_token(
        SerialNumber=mfa_serial,
        TokenCode=token_code
        )
    return res['Credentials']

def assume_role(session, role, mfa_serial=None, mfa_code=None):
    rest = {}
    if mfa_serial:
        token_code = mfa_code or get_token_code()
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

def get_profile_env(config, profile, mfa_code=None):
    section = config[section_name(profile)]

    ret = {'AWS_PROFILE': profile}

    if 'source_profile' in section:
        assert 'role_arn' in section

        print('Using source profile `{}`'.format(section['source_profile']))
        session = boto3.Session(profile_name=section['source_profile'])

        source_section = config[section_name(section['source_profile'])]
        if 'mfa_serial' in section and 'mfa_serial' in section:
            print('Got mfa_serial in both {} and {}'.format(profile, section['source_profile']))
            sys.exit(1)

        if 'mfa_serial' in source_section:
            mfa_serial = source_section['mfa_serial']
        elif 'mfa_serial' in section:
            mfa_serial = source_section['mfa_serial']
        else:
            mfa_serial = None

        # TODO: if source_profile mfa_serial is different than current profile, do we have to do
        #       a get_session_token then an assume role??
        ret.update(to_env(assume_role(session, section['role_arn'], mfa_serial, mfa_code)))

    elif 'mfa_serial' in section:
        session = boto3.Session(profile_name=profile)
        ret.update(to_env(get_session_token(session, section['mfa_serial'], mfa_code)))

    return ret

def to_elisp_env(kv):
    k, v = kv
    return f'(setenv "{k}" "{v}")'

def to_shell_env(kv):
    k, v = kv
    return f'{k}="{v}"'

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('profile')
    parser.add_argument('rest', nargs='*', default=('bash', '--noprofile'))
    parser.add_argument('--elisp', default=False, action='store_true')
    parser.add_argument('--shell', default=False, action='store_true')
    parser.add_argument('--code', default=None, required=False)
    args = parser.parse_args()

    config = load_config(os.getenv('AWS_CONFIG_FILE', '~/.aws/config'))

    info = get_profile_env(config, args.profile, args.code)

    if args.elisp:
        print('(progn {})'.format('\n'.join(map(to_elisp_env, info.items()))))
    elif args.shell:
        print('\n'.join(map(to_shell_env, info.items())))
    else:
        env = os.environ.copy()
        env.update(info)
        os.execvpe(args.rest[0], args.rest, env)

if __name__ == '__main__':
    main()
