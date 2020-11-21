#!/usr/bin/python
#
# Python bindings for wpa_ctrl (wpa_supplicant/hostapd control interface)
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

from distutils.core import setup, Extension

ext = Extension(name = 'wpaspy',
                sources = ['wpa_ctrl.c',
                           'os_unix.c',
                           'wpaspy.c'],
                extra_compile_args = ["-DCONFIG_CTRL_IFACE",
                                      "-DCONFIG_CTRL_IFACE_UNIX"])

setup(name = 'wpaspy',
      ext_modules = [ext],
      description = 'Python bindings for wpa_ctrl (wpa_supplicant/hostapd)')
