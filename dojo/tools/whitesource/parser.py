import hashlib
from urlparse import urlparse
import re
import json
from dojo.models import Endpoint, Finding

__author__ = 'dr3dd589'



class WhitesourceJSONParser(object):
    def __init__(self, file, test):
        self.dupes = dict()
        self.items = ()
        if file is None:
            return
