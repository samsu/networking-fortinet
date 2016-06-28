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


from neutron.db import api as db_api
from oslo_config import cfg
from oslo_log import helpers as log_helpers
import six

from networking_fortinet._i18n import _LE
from networking_fortinet.api_client import client
from networking_fortinet.common import singleton, utils
from networking_fortinet.common import constants as const
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


class FortigateBase(object):
    def __init__(self, fortigate, task_manager=None):
        self.fortigate = fortigate
        if task_manager:
            self.task_manager = task_manager
        else:
            self.task_manager = tasks.TaskManager()
            self.task_manager.start()


class Router(FortigateBase):
    def __init__(self, fortigate, task_manager=None):
        super(Router, self).__init__(fortigate, task_manager=task_manager)
        self.fortigate = fortigate
        # A bunch of resources in the Fortigate
        self.vdom = None

    @log_helpers.log_method_call
    def create(self, router):
        LOG.debug("create_router: router=%s" % (router))
        # Limit one router per tenant
        if not router.get('router', None):
            return
        tenant_id = router['router']['tenant_id']
        if fortinet_db.query_count(context, l3_db.Router,
                                   tenant_id=tenant_id):
            raise Exception(_("FortinetL3ServicePlugin:create_router "
                              "Only support one router per tenant"))
        with context.session.begin(subtransactions=True):
            try:
                namespace = utils.add_vdom(self, context, tenant_id=tenant_id)
                utils.add_vlink(self, context, namespace.vdom)
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("Failed to create_router router=%(router)s"),
                              {"router": router})
                    utils.rollback_on_err(self, context, e)
        utils.update_status(self, context, t_consts.TaskStatus.COMPLETED)
        return super(FortinetL3ServicePlugin, self).\
            create_router(context, router)