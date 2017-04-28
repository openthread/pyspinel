#
#  Copyright (c) 2016-2017, The OpenThread Authors.
#  All rights reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
""" Module-wide logging configuration for spinel package. """

import logging
import logging.config

DEBUG_ENABLE = 0

DEBUG_TUN = 0
DEBUG_HDLC = 0

DEBUG_STREAM_TX = 0
DEBUG_STREAM_RX = 0

DEBUG_LOG_PKT = DEBUG_ENABLE
DEBUG_LOG_SERIAL = DEBUG_ENABLE
DEBUG_LOG_PROP = DEBUG_ENABLE
DEBUG_CMD_RESPONSE = 0
DEBUG_EXPERIMENTAL = 1

LOGGER = logging.getLogger(__name__)

logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers': False,

    'formatters': {
        'minimal': {
            'format': '%(message)s'
        },
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': {
        'console': {
            #'level':'INFO',
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
        },
        #'syslog': {
        #    'level':'DEBUG',
        #    'class':'logging.handlers.SysLogHandler',
        #    'address': '/dev/log'
        #},
    },
    'loggers': {
        'spinel': {
            'handlers': ['console'],  # ,'syslog'],
            'level': 'DEBUG',
            'propagate': True
        }
    }
})


def debug_set_level(level):
    """ Set logging level for spinel module. """
    global DEBUG_ENABLE, DEBUG_LOG_PROP
    global DEBUG_LOG_PKT, DEBUG_LOG_SERIAL
    global DEBUG_STREAM_RX, DEBUG_STREAM_TX, DEBUG_HDLC

    # Defaut to all logging disabled

    DEBUG_ENABLE = 0
    DEBUG_LOG_PROP = 0
    DEBUG_LOG_PKT = 0
    DEBUG_LOG_SERIAL = 0
    DEBUG_HDLC = 0
    DEBUG_STREAM_RX = 0
    DEBUG_STREAM_TX = 0

    if level:
        DEBUG_ENABLE = level
        if level >= 1:
            DEBUG_LOG_PROP = 1
        if level >= 2:
            DEBUG_LOG_PKT = 1
        if level >= 3:
            DEBUG_LOG_SERIAL = 1
        if level >= 4:
            DEBUG_HDLC = 1
        if level >= 5:
            DEBUG_STREAM_RX = 1
            DEBUG_STREAM_TX = 1

    print("DEBUG_ENABLE = " + str(DEBUG_ENABLE))
