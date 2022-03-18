# -*- encoding: utf-8 -*-
"""
@File    : setup.py.py
@Author  : zhouys4
"""
from distutils.core import setup
setup(name='st2-auth-backend-adfs',
      version='1.0',
      py_modules=['st2-auth-backend-adfs'],
      zip_safe=False,
      entry_points={
            'st2auth.sso.backends': [
                  'saml2 = st2auth_sso_adfs.adfs_backend:ADFSAuthenticationBackend'
            ]
      }
      )
