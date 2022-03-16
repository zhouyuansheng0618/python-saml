# -*- encoding: utf-8 -*-
"""
@File    : adfs_backend.py
@Author  : zhouys4
"""

from __future__ import absolute_import

import json
import logging
import uuid
import requests
import saml2
import saml2.config
import saml2.client
import six

LOG = logging.getLogger(__name__)

__all__ = ['ADFSAuthenticationBackend']


class ADFSAuthenticationBackend(object):

    def __int__(self, entity_id, metadata, debug=False):
        if not metadata:
            raise ValueError('metadata exception.')
        if not entity_id:
            raise ValueError("must be entity_id")
        self.relay_state_id = uuid.uuid4().hex
        self.entity_id = entity_id
        self.https_acs_url = '%s/auth/adfs' % entity_id
        self.saml_metadata_url = metadata
        self.saml_metadata = requests.get(self.saml_metadata_url)
        self.saml_client_settings = {
            'entityid': entity_id,
            'metadata': {
                'inline': [self.saml_metadata.text]
            },
            'service': {
                'sp': {
                    'endpoints': {
                        'assertion_consumer_service': [
                            (self.https_acs_url, saml2.BINDING_HTTP_REDIRECT),
                            (self.https_acs_url, saml2.BINDING_HTTP_POST)
                        ],
                    },
                    'allow_unknown_attributes': True,
                    'force_authn': False,
                    'name_id_format_allow_create': False,
                    'want_response_signed': True,
                    'authn_requests_signed': False,
                    'logout_requests_signed': True,
                    'want_assertions_signed': True,
                    'only_use_keys_in_metadata': True,
                    'allow_unsolicited': True,
                }
            },
            'organization': {
                'name': [('url', 'es'), ('url', 'en')],
                'display_name': [('url', 'es'), ('url', 'en')],
                'url': [('url', 'es'),
                        ('url', 'en')],
            },

        }
        if debug:
            self.saml_client_settings['debug'] = 1

    # 获取relay_state_id
    def get_relay_state_id(self):
        return self.relay_state_id

    # 获取saml客户端
    def get_saml_client(self):
        saml_config = saml2.config.Config()
        saml_config.load(self.saml_client_settings)
        saml_config.allow_unknown_attributes = True

        return saml2.client.Saml2Client(config=saml_config)

    # 获取请求重定向的url
    def get_redirect_url(self, referer):

        if not referer.startswith(self.entity_id):
            raise ValueError('entity_id Validation fails.')
        relay_state = {
            'id': self.relay_state_id,
            'referer': referer
        }
        saml_client = self.get_saml_client()
        reqid, info = saml_client.prepare_for_authenticate(
            relay_state=json.dumps(relay_state))

        redirect_url = \
            [v for k, v in six.iteritems(dict(info['headers'])) if
             k == 'Location'][
                0]

        return redirect_url

    # 验证 SAMLResponse
    def verify_response(self, response):
        try:
            if not hasattr(response, 'SAMLResponse'):
                raise ValueError(
                    'SAMLResponse does not exist.')

            if getattr(response, 'SAMLResponse', None) is None:
                raise ValueError(
                    'The SAMLResponse attribute is null.')

            if len(getattr(response, 'SAMLResponse')) <= 0:
                raise ValueError(
                    'The SAMLResponse attribute is empty.')
            has_relay_state = hasattr(response, 'RelayState')

            if has_relay_state and getattr(response, 'RelayState',
                                           None) is None:
                raise ValueError(
                    'The RelayState attribute is null.')
            if has_relay_state and len(getattr(response, 'RelayState')) <= 0:
                raise ValueError(
                    'The RelayState attribute is empty.')

            relay_state = json.loads(
                getattr(response, 'RelayState')[0]) if has_relay_state else {}

            if (has_relay_state and (
                    'id' not in relay_state or 'referer' not in relay_state or
                    self.get_relay_state_id() != relay_state['id'] or
                    not relay_state['referer'].startswith(self.entity_id))):
                error_message = 'The value of the RelayState in the response does not match.'
                raise ValueError(error_message)

            # Parse the response and verify signature.
            saml_response = getattr(response, 'SAMLResponse')[0]
            saml_client = self.get_saml_client()

            authn_response = saml_client.parse_authn_request_response(
                saml_response,
                saml2.BINDING_HTTP_POST
            )

            if not authn_response:
                raise ValueError('SAMLRespons parsing failed.')

            verified_user = {
                'referer': relay_state.get('referer') or self.entity_id,
                'username': str(authn_response.ava['Username'][0]),
                'email': str(authn_response.ava['Email'][0]),
                'last_name': str(authn_response.ava['LastName'][0]),
                'first_name': str(authn_response.ava['FirstName'][0])
            }
        except Exception:
            message = 'SAML2 authentication failed. Procedure'
            LOG.exception(message)
            raise ValueError(message)

        return verified_user
