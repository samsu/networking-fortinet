# Copyright 2015 Fortinet Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


from neutron.agent.l3 import router_info as router
from neutron.db import api as db_api
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_utils import excutils
import six

from networking_fortinet._i18n import _LE
from networking_fortinet.api_client import client
from networking_fortinet.api_client import exception
from networking_fortinet.common import constants as const
from networking_fortinet.common import resources as resources
from networking_fortinet.common import singleton, utils
from networking_fortinet.common.config import LOG
from networking_fortinet.db import models as fortinet_db
from networking_fortinet.tasks import constants as t_consts
from networking_fortinet.tasks import tasks


@singleton.singleton
class Fortigate(object):

    @log_helpers.log_method_call
    def __init__(self, task_manager=None):
        """Fortigate class."""
        self.cfg = getattr(cfg.CONF, const.CONF_SECTION, None)
        self.api_client = self.get_apiclient()

        if not task_manager:
            task_manager = tasks.TaskManager()
        self.task_manager = task_manager
        self.task_manager.start()

    @log_helpers.log_method_call
    def initialize(self):
        if not getattr(self.cfg, 'address', None):
            # samsu: it means use general network nodes instead of a fgt
            return

        for key in const.FORTINET_PARAMS:
            self.sync_conf_to_db(key)
        self.setup_env()

    @log_helpers.log_method_call
    def setup_env(self):
        # Prepare a fortigate vdom for external network in advance
        session = db_api.get_session()
        try:
            utils.add_vdom(self, session, vdom=const.EXT_VDOM,
                           tenant_id=const.FAKE_TENANT_ID)
            utils.set_vlanintf(self, session, vdom=const.EXT_VDOM,
                               name=self.cfg.ext_interface)
        except Exception as e:
            utils.rollback_on_err(self, session, e)
            raise e
        utils.update_status(self, session, t_consts.TaskStatus.COMPLETED)

    @log_helpers.log_method_call
    def get_apiclient(self):
        """Fortinet api client initialization."""
        if not self.cfg.address:
            return None

        api_server = [(self.cfg.address, self.cfg.port,
                       'https' == self.cfg.protocol)]
        return client.FortiosApiClient(
            api_server, self.cfg.username, self.cfg.password)

    @log_helpers.log_method_call
    def sync_conf_to_db(self, param):
        cls = getattr(fortinet_db, const.FORTINET_PARAMS[param]['cls'])
        conf_list = self.get_range(param)
        session = db_api.get_session()
        records = fortinet_db.query_records(session, cls)
        for record in records:
            kwargs = {}
            for key in const.FORTINET_PARAMS[param]['keys']:
                _element = const.FORTINET_PARAMS[param]['type'](record[key])
                if _element not in conf_list and not record.allocated:
                    kwargs.setdefault(key, record[key])
                    fortinet_db.delete_record(session, cls, **kwargs)
        try:
            for i in range(0, len(conf_list),
                           len(const.FORTINET_PARAMS[param]['keys'])):
                kwargs = {}
                for key in const.FORTINET_PARAMS[param]['keys']:
                    kwargs.setdefault(key, str(conf_list[i]))
                    i += 1
                cls.init_records(session, **kwargs)
        except IndexError:
            LOG.error(_LE("The number of the configure range is not even,"
                        "the last one of %(param)s can not be used"),
                      {'param': param})
            raise IndexError

    @log_helpers.log_method_call
    def get_range(self, param):
        _type = const.FORTINET_PARAMS[param]['type']
        if const.FORTINET_PARAMS[param]['format']:
            min, max = self.cfg[param].split(const.FIELD_DELIMITER)
            if _type(min) > _type(max):
                min, max = max, min
            if _type == int:
                min, max = _type(min), _type(max) + 1
            result = const.FORTINET_PARAMS[param]['range'](min, max)
        else:
            result = const.FORTINET_PARAMS[param]['range'](
                                _type(self.cfg[param]),
                                const.FORTINET_PARAMS[param]['netmask'])

        return result if isinstance(result, list) else list(result)


class Base(object):
    def __init__(self, fortigate, task_manager=None, *args, **kwargs):
        self.fortigate = fortigate
        self.api_client = fortigate.api_client
        if task_manager:
            self.task_manager = task_manager
        else:
            self.task_manager = tasks.TaskManager()
            self.task_manager.start()

    def getid(self, context):
        id = getattr(context, 'request_id', None)
        if not id:
            if not getattr(context, 'session', None):
                return const.INIT_TASK_ID
            else:
                raise ValueError("not get request_id")
        return id

    def op(self, func, task_id=None, **data):
        res = func(self.api_client, data)
        if task_id and res.get('rollback', {}):
            self.task_manager.add(task_id, **res['rollback'])
        return res.get('result', res)

    def rollback(self, task_id):
        if task_id:
            self.task_manager.update_status(task_id,
                                            t_consts.TaskStatus.ROLLBACK)

    def finish(self, task_id):
        if task_id:
            self.task_manager.update_status(task_id,
                                            t_consts.TaskStatus.COMPLETED)

    def add_resource(self, task_id, resource, **kwargs):
        return self.op(resource.add, task_id=task_id, **kwargs)

    def set_resource(self, task_id, resource, **kwargs):
        return self.op(resource.set, task_id=task_id, **kwargs)

    def delete_resource(self, task_id, resource, **kwargs):
        return self.op(resource.delete, task_id=task_id, **kwargs)


class Router(Base, router.RouterInfo):
    def __init__(self, fortigate, task_manager=None, *args, **kwargs):
        self.fortigate = fortigate
        # A bunch of resources in the Fortigate
        self.cfg = None
        super(Router, self).__init__(fortigate, task_manager=task_manager, *args, **kwargs)

    @log_helpers.log_method_call
    def create_router(self, router):
        # Limit one router per tenant
        cfg = router.get('fortigate', None)
        if not cfg:
            return
        res = {}
        task_id = router.get('id', None)
        try:
            if 'vdom' in cfg:
                self.add_resource(task_id, resources.Vdom,
                                  name=cfg['vdom']['vdom'])
            if 'vlink' in cfg:
                vlinkinfo = cfg['vlink']
                if 'vdomlink' in vlinkinfo:
                    self.add_resource(task_id, resources.VdomLink,
                                      name=vlinkinfo['vdomlink']['name'])
                if 'vlaninterface' in vlinkinfo:
                    for inf in vlinkinfo['vlaninterface']:
                        self.set_resource(task_id, resources.VlanInterface,
                                          **inf)
                if 'routestatic' in vlinkinfo:
                    r = self.add_resource(task_id, resources.RouterStatic,
                                          **vlinkinfo['routestatic'])
                    if 'ADD' == r['http_method']:
                        res['routestatic'] = vlinkinfo['routestatic']
                        res['routestatic']['edit_id'] = r['results']['mkey']

        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to create_router router=%(router)s"),
                          {"router": router})
                self.rollback(task_id)
        self.finish(task_id)
        return res

    def process(self, agent):
        # After a router was added to the dict, still need to process
        # other things .e.g. ports
        ex_gw_port = self.get_ex_gw_port()
        if ex_gw_port:
            import ipdb;ipdb.set_trace()
            self.fip_ns = agent.get_fip_ns(ex_gw_port['network_id'])
            #self.fip_ns.scan_fip_ports(self)

        #super(Router, self).process(agent)
