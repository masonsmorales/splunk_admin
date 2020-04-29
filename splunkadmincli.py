# alternative CLI client for Splunk by duane waddle
# kinda crazy, but crazy useful
# related tools:
#   - https://github.com/harsmarvania57/splunk-ko-change 
#   - https://github.com/gjanders/Splunk
from __future__ import print_function
import sys
import os
import os.path
import requests
import argparse
import urllib
import pprint
import json
import logging
import time
import re
from requests.auth import HTTPBasicAuth


# Because of how seldom a Splunk instance is set up with good certs
#requests.packages.urllib3.disable_warnings()
#ssl_verify = False

logger=logging.getLogger(sys.argv[0])
logger.setLevel(logging.DEBUG)

# create console handler and set level to debug
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
# create formatter
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
# add formatter to ch
ch.setFormatter(formatter)
# add ch to logger
logger.addHandler(ch)


class FileTypeNoOverwrite(argparse.FileType):

    def __init__ (self,mode='r',bufsize=-1):
        super(FileTypeNoOverwrite,self).__init__(mode,bufsize)

    def __call__(self, string):
        if string != '-' and os.path.exists(string):
            raise argparse.ArgumentTypeError("Can't overwrite %s" % string)
        else:
            #return argparse.FileType.__call__(self,string)
            return super(FileTypeNoOverwrite,self).__call__(string)


class SavedSearcher:

    def __init__(self,url,rest_user,rest_pass,ssl_verify=False):
        self.auth=HTTPBasicAuth(rest_user,rest_pass)
        self.ssl_verify=ssl_verify
        self.server_url=url
        self.rest_user=rest_user
        self.rest_pass=rest_pass



        # The 'directory' admin endpoint that has a list of MOST of the KOs in it
        # There's a bug in directory, not everything shown here.  See SPL-127492
        self.directory_urls = [
            'admin/directory',
            'data/props/calcfields',
            'admin/macros',
            'data/models',
            'data/lookup-table-files',
            'admin/viewstates',

            # Sourcetypes aren't really owned by a person so makes no sense to try
            # to move them under the scope of a user change... but it we try to move
            # 'nobody' -- WHICH IS VALID -- then yeah
            'admin/sourcetypes',
            'admin/indexes',
        ]


    def list_saved_searches(self,app_name,list_enabled,list_disabled):

	tokens = [ ]
        if(list_enabled):
            tokens.append('disabled=0')
        if(list_disabled):
            tokens.append('disabled=1')

        if(len(tokens) > 0):
            enabled_disabled = 'AND ( ' + ' OR '.join(tokens) + ' )'
        else:
            enabled_disabled=''

        search=''.join( [ 'eai:acl.app=', app_name, ' AND eai:acl.modifiable=1 ', enabled_disabled  ] )
        logger.debug(search)

        for i in self.get_KOs_by_search(search,'admin/savedsearch',app_name=app_name):
            logger.info("Search %s user=%s scheduled=%s state=%s" % ( i.get('name',i.get('id')), i['acl'].get('owner'),
                       i['content'].get('is_scheduled'), ('disabled' if i['content'].get('disabled') else 'enabled') ) )


    def disable_saved_searches(self,app_name,output_file):
        urls = [ ]
        search=''.join( [ 'eai:acl.app=', app_name, ' AND eai:acl.modifiable=1 AND is_scheduled=1 AND disabled=0' ] )
        for i in self.get_KOs_by_search(search,'admin/savedsearch',app_name=app_name):
            if self.set_search_disabled_state(i['id'],True):
                logger.info("Disabled search %s" % i.get('name',i.get('id')))
	        urls.append(i['id'])
                json.dump(urls,output_file,indent=4, sort_keys=True)
                output_file.seek(0)


    def enable_saved_searches(self,app_name,input_file):
        urls = json.load(input_file)
        for i in urls:
            if self.set_search_disabled_state(i,False):
                logger.info("Enabled search %s" % i)


    def cron_shift_saved_searches(self,app_name,offset=0):
        search=''.join( [ 'eai:acl.app=', app_name, ' AND eai:acl.modifiable=1' ] )
        for i in self.get_KOs_by_search(search,'admin/savedsearch',app_name=app_name):
            cron=i['content'].get('cron_schedule','')
            if cron != '' and not cron.split()[1].startswith('*'):
                cron_components=cron.split()
                # Deep down in the rabbit hole here, within the 'hour'
                # Treat "," as major sep and "-" as minor

                majors = [ ]
                for major in re.split(",",cron_components[1]):
                    minors=[ ]
                    for minor in re.split("-",major):
                        new_hour=int(minor)+int(offset)

                        # I mean technically here I should also handle reverse offsets
                        # and dropping down to negative minutes, but it's ultra rare and
                        # not at all pretty.
                        if new_hour > 23:
                            new_hour = new_hour % 24
                        minors.append(new_hour)


                    # handle half-split around midnight
                    if (len(minors) == 2) and (minors[0] > minors [1]):
                        newminors = [ 0 , minors[1] ]
                        minors[1]=23
                        majors.append('-'.join([ str(x) for x in minors]))
                        majors.append('-'.join([ str(x) for x in newminors]))
                    else:
                        majors.append('-'.join([str(x) for x in minors]))
                new_hour=','.join(majors)
                cron_components[1]=new_hour
                new_cron=' '.join(cron_components)

                #logger.debug("old=%s" % cron)
                #logger.debug("new=%s" % new_cron)

                if self.update_entity(''.join([self.server_url,i['links']['edit']]),{ 'cron_schedule' : new_cron }):
                    logger.info("Updated schedule for %s from '%s' to '%s'" % (i['name'],cron,new_cron))


    def nuke_all_user_private_in_app(self,source_app,user="-"):
        search = ' AND '.join(['eai:acl.app='+source_app,'eai:acl.sharing=user'])

        if user != "-":
            search = ' AND '.join([search,'eai:acl.owner='+user])

        for e in self.directory_urls:
            for i in self.get_KOs_by_search(search,e,app_name=source_app,user_name=user):
                if self.delete_entity(''.join([self.server_url,i['links']['edit']])):
                    logger.info('Deleted user="%s"type="%s" name="%s"' % (i.get('acl',{}).get('owner'),i.get('content',{}).get('eai:type'),i['name']))

    def set_search_disabled_state(self,id,disabled_state):

        post_data= {
            'disabled' : disabled_state
        }
        return self.update_entity(id,post_data)

    def update_entity(self,id,updates):

        args= {
            'output_mode' : 'json'
        }

        r = requests.post(id, auth=self.auth, verify=self.ssl_verify, params=args, data=updates)

        if r.status_code == requests.codes.ok:
            return True
        else:
            logger.error("Request to %s returned %d" % (r.url, r.status_code))
            logger.info(r.text)
            return False


    def delete_entity(self,id):

        args= {
            'output_mode' : 'json'
        }

        r = requests.delete(id, auth=self.auth, verify=self.ssl_verify, params=args)

        if r.status_code == requests.codes.ok:
            return True
        else:
            logger.error("Request to %s returned %d" % (r.url, r.status_code))
            logger.info(r.text)
            return False

    def get_KOs_by_search(self,search,endpoint,user_name="-",app_name="-"):

        args= {
            'count' : '-1',
            'output_mode' : 'json',
            #'search' : ''.join(['eai:acl.owner=',user_name,' AND ','eai:acl.app=',app_name])
            'search' : search
        }

        #url = '/'.join([self.server_url,'servicesNS',user_name,app_name,'admin/savedsearch'])
        url = '/'.join([self.server_url,'servicesNS',user_name,app_name,endpoint])

        r = requests.get(url, auth=self.auth, verify=self.ssl_verify, params=args)

        if r.status_code == requests.codes.ok:
            q=r.json()
            for e in q.get('entry',[]):
                #logger.debug(pprint.pformat(e))
                yield e
        else:
            logger.error("Request to %s returned %d" % (r.url, r.status_code))
            logger.info(r.text)

def add_common_args(x):
    x.add_argument("auth_user",  help="User to auth to rest api as")
    x.add_argument("auth_pass",  help="Pass to auth to rest api as")
    x.add_argument("source_app",  help="app context")

if __name__ == "__main__" :
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", help="Server URL",default="https://localhost:8089")

    subparsers=parser.add_subparsers(help='sub-command help',dest='subcommand')
    disable=subparsers.add_parser('savedsearch-disable',help='disable enabled scheduled searches in app')
    add_common_args(disable)
    disable.add_argument("--output", help="output file",required=True,type=FileTypeNoOverwrite('w'))

    enable=subparsers.add_parser('savedsearch-enable',help='enable saved searches using input file')
    add_common_args(enable)
    enable.add_argument("--input", help="input file",required=True,type=argparse.FileType('r'))

    list=subparsers.add_parser('savedsearch-list',help='list saved searches')
    add_common_args(list)
    list.add_argument("--enabled", action="store_true")
    list.add_argument("--disabled", action="store_true")

    shift=subparsers.add_parser('savedsearch-cronshift',help='shift cron schedule for TZ')
    add_common_args(shift)
    shift.add_argument("offset",help='TZ offset in hours as integer')

    delete=subparsers.add_parser('deleteAllUserKOs',help='delete all private KOs')
    add_common_args(delete)

    delete2=subparsers.add_parser('deleteOneUserKOs',help='delete user private KOs')
    add_common_args(delete2)
    delete2.add_argument("user",help='The poor unfortunate soul')

    args=parser.parse_args()

    K = SavedSearcher(args.server,args.auth_user,args.auth_pass)

    if args.subcommand == 'savedsearch-disable':
        K.disable_saved_searches(args.source_app,args.output)
    elif args.subcommand == 'savedsearch-enable':
        K.enable_saved_searches(args.source_app,args.input)
    elif args.subcommand == 'savedsearch-list':
        K.list_saved_searches(args.source_app,args.enabled,args.disabled)
    elif args.subcommand == 'savedsearch-cronshift':
        K.cron_shift_saved_searches(args.source_app,args.offset)
    elif args.subcommand == 'deleteAllUserKOs':
        K.nuke_all_user_private_in_app(args.source_app)
    elif args.subcommand == 'deleteOneUserKOs':
        K.nuke_all_user_private_in_app(args.source_app,args.user)
