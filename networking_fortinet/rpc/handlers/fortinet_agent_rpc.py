# Copyright 2016 Fortinet, Inc.
# All rights reserved.
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


from datetime import datetime
import functools
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import oslo_messaging
from oslo_utils import excutils
from oslo_utils import timeutils
from oslo_utils import uuidutils

from neutron.agent.l3 import agent
from neutron.api.rpc.handlers import l3_rpc
from neutron.common import constants
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.plugins.common import constants as p_const
from neutron import context as n_context
from neutron import manager

from networking_fortinet._i18n import _, _LE, _LI
from networking_fortinet.common import constants as const
from networking_fortinet.common import utils
from networking_fortinet.db import models as fortinet_db
from networking_fortinet.tasks import constants as t_consts
from networking_fortinet.tasks import tasks

LOG = logging.getLogger(__name__)


def checktimestamp(method):
    """
    compare the start time of rpc server with the message time to be sent,
    if the message generated time is older than the start time, then discard.
    """

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        time = kwargs['time']
        time = timeutils.parse_strtime(time)
        if self.START_TIME > time:
            time_agent = timeutils.isotime(time)
            time_server = timeutils.isotime(self.START_TIME)
            log_dict = {'agent_time': time_agent, 'server_time': time_server}
            LOG.debug("Stale message received with timestamp: %(agent_time)s."
                      "Skipping processing because it's older than the "
                      "server start timestamp: %(server_time)s", log_dict)
            return
        return method(self, *args, **kwargs)

    return wrapper


class FortinetAgentRpcApi(object):
    """Agent-side RPC (stub) for agent-to-plugin interaction.

    This class implements the client side of an rpc interface.  The server side
    can be found below: FortinetAgentRpcCallback. For more information on
    changing rpc interfaces, see doc/source/devref/rpc_api.rst.
    """
    # 1.0 Initial Version

    def __init__(self, topic, host):
        topic = topic if topic else const.FTNT_AGENT
        self.host = host
        fgt_target = oslo_messaging.Target(
            topic=topic, version='1.0')
        self.context = n_context.get_admin_context_without_session()
        self.fgt_client = n_rpc.get_client(fgt_target)

    @log_helpers.log_method_call
    def device_register(self, agent_state, use_call=False):
        cctxt = self.fgt_client.prepare()
        # self.agent_state['uuid'] = uuidutils.generate_uuid()
        agent_state['host'] = self.host
        kwargs = {
            'agent_state': {'agent_state': agent_state},
            'time': datetime.utcnow().strftime(constants.ISO8601_TIME_FORMAT),
        }
        method = cctxt.call if use_call else cctxt.cast
        return method(self.context, 'device_register', **kwargs)

    @log_helpers.log_method_call
    def get_routers(self, context, router_ids=None):
        """Make a remote process call to retrieve the sync data for routers."""
        cctxt = self.fgt_client.prepare()
        body = {
            'host': self.host,
            'router_ids': router_ids
        }
        kwargs = {
            'body': body,
            'time': datetime.utcnow().strftime(constants.ISO8601_TIME_FORMAT),
        }
        return cctxt.call(context, 'ftnt_sync_routers', **kwargs)

    @log_helpers.log_method_call
    def update_data(self, context, data=None):
        """Make a remote process call to retrieve the sync data for routers."""
        cctxt = self.fgt_client.prepare()
        body = {
            'host': self.host,
            'data': data
        }
        kwargs = {
            'body': body,
            'time': datetime.utcnow().strftime(constants.ISO8601_TIME_FORMAT),
        }
        return cctxt.cast(context, 'update_data', **kwargs)


class FortinetAgentRpcCallback(object):
    """Processes the rpc report in Fortinet plugin implementations.

    This class implements the server side of an rpc interface.  The client side
    can be found in neutron.agent.rpc.PluginReportStateAPI.  For more
    information on changing rpc interfaces, see doc/source/devref/rpc_api.rst.
    """

    target = oslo_messaging.Target(version='1.0')
    START_TIME = timeutils.utcnow()

    def __init__(self, plugin=None, task_manager=None):
        if not task_manager:
            self.task_manager = tasks.TaskManager()
            self.task_manager.start()
        else:
            self.task_manager = task_manager

    @log_helpers.log_method_call
    @checktimestamp
    def device_register(self, context, **kwargs):
        """The first report state when fortinet agent start to server."""
        agent_state = kwargs['agent_state']['agent_state']
        fortigate = fortinet_db.add_record(
            context, fortinet_db.Fortinet_Fortigate, **agent_state)
        return fortigate['result'].make_dict()

    def _check_clock_sync_on_agent_start(self, agent_state, agent_time):
        """Checks if the server and the agent times are in sync.

        Method checks if the agent time is in sync with the server time
        on start up. Ignores it, on subsequent re-connects.
        """
        if agent_state.get('start_flag'):
            time_server_now = timeutils.utcnow()
            diff = abs(timeutils.delta_seconds(time_server_now, agent_time))
            if True:
                LOG.debug("### _check_clock_sync_on_agent_start")
                return

            if diff > cfg.CONF.agent_down_time:
                agent_name = agent_state['agent_type']
                time_agent = timeutils.isotime(agent_time)
                host = agent_state['host']
                log_dict = {'host': host,
                            'agent_name': agent_name,
                            'agent_time': time_agent,
                            'threshold': cfg.CONF.agent_down_time,
                            'serv_time': timeutils.isotime(time_server_now),
                            'diff': diff}
                LOG.error(_LE("Message received from the host: %(host)s "
                              "during the registration of %(agent_name)s has "
                              "a timestamp: %(agent_time)s. This differs from "
                              "the current server timestamp: %(serv_time)s by "
                              "%(diff)s seconds, which is more than the "
                              "threshold agent down"
                              "time: %(threshold)s."), log_dict)

    @log_helpers.log_method_call
    @checktimestamp
    def ftnt_sync_routers(self, context, **kwargs):
        """Sync routers according to filters to a specific agent.

        @param context: contain user information
        @param kwargs: host, router_ids
        @return: a list of routers
                 with their interfaces and floating_ips
        """
        # import ipdb;ipdb.set_trace()
        body = kwargs['body']
        host = body.get('host')
        fortigate = fortinet_db.query_record(
            context, fortinet_db.Fortinet_Fortigate, host=host)
        l3_plugin = manager.NeutronManager.get_service_plugins().get(
            p_const.L3_ROUTER_NAT, None)
        if not l3_plugin:
            return {}
        import ipdb;ipdb.set_trace()
        routers = l3_plugin.endpoints[0].sync_routers(context, **body)
        for router in routers:
            rinfo = self._get_router_info(context, fortigate.id, router)
            rinfo.setdefault('fortigate', fortigate.make_dict())
            router['fortigate'] = rinfo
        return routers

    def _get_router_info(self, context, fortigate_id, router):
        # Limit one router per tenant
        if not router.get('id', None):
            return
        rinfo = {}
        tenant_id = router['tenant_id']
        try:
            namespace = utils.allocate_vdom(self, context, tenant_id=tenant_id)
            rinfo['vdom'] = namespace.make_dict() if namespace else {}
            rinfo['vlink'] = utils.allocate_vlink(self, context, fortigate_id,
                                                  namespace.vdom)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to create_router router=%(router)s"),
                          {"router ": router})
                utils.rollback_on_err(self, context, e)
        utils.update_status(self, context, t_consts.TaskStatus.COMPLETED)
        return rinfo

    @checktimestamp
    def update_data(self, context, **kwargs):
        """Make a remote process call to retrieve the sync data for routers."""
        data = kwargs['body']['data']
        for key in data:
            cls = getattr(fortinet_db, const.DICT_DB_MAPS[key], None)
            if cls:
                cls.update_with_kwargs(context, **data[key])
