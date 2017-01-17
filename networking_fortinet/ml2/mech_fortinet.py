# Copyright 2015 Fortinet, Inc.
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


"""Implentation of Fortinet ML2 Mechanism driver for ML2 Plugin."""


import sys
import netaddr
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from neutron.common import constants as l3_constants
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import api as db_api
from neutron.db import external_net_db as ext_db
from neutron.db import models_v2
from neutron.extensions import portbindings
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import driver_api

from networking_fortinet._i18n import _, _LE, _LI
from networking_fortinet.common import config
from networking_fortinet.common import constants as const
from networking_fortinet.common import fortigate
from networking_fortinet.common import resources as resources
from networking_fortinet.common import utils as utils
from networking_fortinet.db import models as fortinet_db
from networking_fortinet.rpc.handlers import fortinet_agent_rpc
from networking_fortinet.tasks import constants as t_consts
from networking_fortinet.tasks import tasks




LOG = logging.getLogger(__name__)


class FortinetMechanismDriver(driver_api.MechanismDriver):
    """ML2 Mechanism driver for Fortinet devices."""

    @log_helpers.log_method_call
    def __init__(self):
        super(FortinetMechanismDriver, self).__init__()
        self.fortigate = None
        self.api_client = None
        self.task_manager = tasks.TaskManager()
        self.task_manager.start()

    @log_helpers.log_method_call
    def check_segment_for_agent(self, segment, agent):
            mappings = agent['configurations'].get('bridge_mappings', {})
            tunnel_types = agent['configurations'].get('tunnel_types', [])
            LOG.debug("Checking segment: %(segment)s "
                      "for mappings: %(mappings)s "
                      "with tunnel_types: %(tunnel_types)s",
                      {'segment': segment, 'mappings': mappings,
                       'tunnel_types': tunnel_types})
            network_type = segment[driver_api.NETWORK_TYPE]
            if network_type == 'local':
                return True
            elif network_type in tunnel_types:
                return True
            elif network_type in ['flat', 'vlan']:
                return segment[driver_api.PHYSICAL_NETWORK] in mappings
            else:
                return False

    @log_helpers.log_method_call
    def initialize(self):
        """Initilize of variables needed by this class."""
        self.Fortinet_init()

    @log_helpers.log_method_call
    def Fortinet_init(self):
        """Fortinet specific initialization for this class."""
        LOG.debug("FortinetMechanismDriver_init")
        self.fortigate = fortigate.Fortigate(task_manager=self.task_manager)
        self.api_client = self.fortigate.get_apiclient()
        self.fortigate.initialize()
        self.setup_rpc()

    @log_helpers.log_method_call
    def setup_rpc(self):
        """Start the RPC loop to let the plugin communicate with agents."""
        #cfg.CONF.import_opt('router_distributed', 'DEFAULT')
        #if getattr(cfg.CONF, 'router_distributed', False):
        LOG.debug("FortinetMechanismDriver_setup_rpc")
        #self.topic = topics.L3PLUGIN
        self.topic = const.FTNT_AGENT
        self.conn = n_rpc.create_connection(new=True)
        self.endpoints = [fortinet_agent_rpc.FortinetAgentRpcCallback(
            task_manager=self.task_manager)]
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)
        self.conn.consume_in_threads()

    @log_helpers.log_method_call
    def create_network_precommit(self, mech_context):
        """Create Network in the mechanism specific database table."""
        LOG.debug("create_network_precommit: called")
        pass

    @log_helpers.log_method_call
    def create_network_postcommit(self, mech_context):
        """Create Network as a portprofile on the fortigate."""
        LOG.debug("create_network_postcommit: called")
        network = mech_context.current
        if network["router:external"]:
            # TODO(samsu)
            return
        # use network_id to get the network attributes
        # ONLY depend on our db for getting back network attributes
        # this is so we can replay postcommit from db
        network_name = network['name']
        tenant_id = network['tenant_id']
        segment = mech_context.network_segments[0]
        # currently supports only one segment per network
        if segment['network_type'] != 'vlan':
            raise Exception(_("Fortinet Mechanism: failed to create network,"
                              "only network type vlan is supported"))

        vlanid = segment['segmentation_id']
        context = mech_context._plugin_context
        try:
            namespace = utils.add_vdom(self, context, tenant_id=tenant_id)
            if not namespace:
                raise
            # TODO(samsu): type driver support vlan only,
            # need to check later
            inf_name = const.PREFIX['inf'] + str(vlanid)
            utils.add_vlanintf(self, context,
                               name=inf_name,
                               vdom=namespace.vdom,
                               vlanid=vlanid,
                               interface=self.fortigate.cfg['int_interface'],
                               alias=network_name)
        except Exception as e:
            utils.rollback_on_err(self, context, e)
            raise ml2_exc.MechanismDriverError(
                method=sys._getframe().f_code.co_name)
        utils.update_status(self, context, t_consts.TaskStatus.COMPLETED)

    @log_helpers.log_method_call
    def delete_network_precommit(self, mech_context):
        """Delete Network from the plugin specific database table."""
        LOG.debug("delete_network_precommit: called")
        network = mech_context.current
        network_id = network['id']
        context = mech_context._plugin_context
        if fortinet_db.query_record(context, ext_db.ExternalNetwork,
                                    network_id=network_id):
            # return when the network is external network
            # TODO(samsu): may check external network
            # before delete namespace
            return
        tenant_id = network['tenant_id']
        namespace = fortinet_db.query_record(context,
                                    fortinet_db.Fortinet_ML2_Namespace,
                                    tenant_id=tenant_id)
        if not namespace:
            return
        # TODO(samsu): type driver support vlan only,
        # need to check later
        vlanid = network['provider:segmentation_id']
        inf_name = const.PREFIX['inf'] + str(vlanid)
        try:
            utils.delete_vlanintf(self, context, name=inf_name,
                     vdom=namespace.vdom)
        except Exception as e:
            resources.Exinfo(e)
            raise ml2_exc.MechanismDriverError(
                method=sys._getframe().f_code.co_name)

    @log_helpers.log_method_call
    def delete_network_postcommit(self, mech_context):
        """Delete network which translates to remove vlan interface
        and related vdom from the fortigate.
        """
        LOG.debug("delete_network_postcommit: called")
        network = mech_context.current
        context = mech_context._plugin_context
        tenant_id = network['tenant_id']
        with context.session.begin(subtransactions=True):
            try:
                utils.delete_vdom(self, context, tenant_id=tenant_id)
                LOG.info(_LI("delete network postcommit: tenant= %(tenant_id)s"
                           " network= %(network)s"),
                         {'tenant_id': tenant_id, 'network': network})
            except Exception as e:
                resources.Exinfo(e)
                raise ml2_exc.MechanismDriverError(
                    method=sys._getframe().f_code.co_name)

    @log_helpers.log_method_call
    def update_network_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        cur_network = mech_context.current
        org_network = mech_context.original
        if cur_network["router:external"] != org_network["router:external"]:
            LOG.info(_LI("update_network_precommit failed: the external "
                         "attribute cannot be updated, instead of updating the"
                         " attribute, the external network only support "
                         "creation from scratch on the admin view. \nThe "
                         "org_network: %(org)s, \nthe cur_network %(cur)s"),
                     {'org': org_network, 'cur': cur_network})
            raise NotImplementedError("The external attribute cannot be "
                                      "updated")
        pass

    @log_helpers.log_method_call
    def update_network_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        pass

    @log_helpers.log_method_call
    def create_subnet_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug("create_subnetwork_precommit: called")

    @log_helpers.log_method_call
    def create_subnet_postcommit(self, mech_context, update=False):
        if not update:
            LOG.debug("create_subnetwork_postcommit: called")
        gateway = mech_context.current['gateway_ip']
        network_id = mech_context.current['network_id']
        subnet_id = mech_context.current['id']
        tenant_id = mech_context.current['tenant_id']
        context = mech_context._plugin_context
        dns_nameservers = mech_context.current.setdefault(
            'dns_nameservers', [])
        if update:
            router_func = utils.set_routerstatic
            dhcp_func = utils.set_dhcpserver
        else:
            router_func = utils.add_routerstatic
            dhcp_func = utils.add_dhcpserver
        try:
            if fortinet_db.query_record(context, ext_db.ExternalNetwork,
                                        network_id=network_id):

                router_func(self, context,
                            subnet_id=subnet_id,
                            vdom=const.EXT_VDOM,
                            dst=const.EXT_DEF_DST,
                            device=self.fortigate.cfg['ext_interface'],
                            gateway=gateway)
            else:
                namespace = fortinet_db.query_record(context,
                                        fortinet_db.Fortinet_ML2_Namespace,
                                        tenant_id=tenant_id)
                interface = utils.get_intf(context,
                                           mech_context.current['network_id'])
                netmask = str(netaddr.
                            IPNetwork(mech_context.current['cidr']).netmask)
                start_ip = mech_context.current['allocation_pools'][0]['start']
                end_ip = mech_context.current['allocation_pools'][0]['end']
                dhcp_func(self, context,
                          subnet_id=subnet_id,
                          vdom=namespace.vdom,
                          interface=interface,
                          dns_nameservers=dns_nameservers,
                          gateway=gateway,
                          netmask=netmask,
                          start_ip=start_ip,
                          end_ip=end_ip)

                # TODO(samsu): need to add rollback for the update and set
                cls = fortinet_db.Fortinet_Interface
                record = fortinet_db.query_record(context, cls,
                                                  name=interface,
                                                  vdom=namespace.vdom)
                if gateway:
                    cls.update_record(context, record,
                                      ip="%s %s" % (gateway, netmask))
                    utils.op(self, context, resources.VlanInterface.set,
                             name=interface,
                             vdom=namespace.vdom,
                             ip="%s %s" % (gateway, netmask))
        except Exception as e:
            utils.rollback_on_err(self, context, e)
            raise ml2_exc.MechanismDriverError(
                method=sys._getframe().f_code.co_name)
        if not update:
            utils.update_status(self, context, t_consts.TaskStatus.COMPLETED)

    @log_helpers.log_method_call
    def delete_subnet_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug("delete_subnetwork_precommit: called")

    @log_helpers.log_method_call
    def delete_subnet_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug("delete_subnet_postcommit: called")
        context = mech_context._plugin_context
        subnet_id = mech_context.current['id']
        try:
            utils.delete_routerstatic(self, context, subnet_id=subnet_id)
            utils.delete_dhcpserver(self, context, subnet_id=subnet_id)
        except Exception as e:
            resources.Exinfo(e)
            raise ml2_exc.MechanismDriverError(
                method=sys._getframe().f_code.co_name)

    @log_helpers.log_method_call
    def update_subnet_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug("update_subnet_precommit: called")

    @log_helpers.log_method_call
    def update_subnet_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug("update_subnet_postcommit: called")
        self.create_subnet_postcommit(mech_context, update=True)

    @log_helpers.log_method_call
    def create_port_precommit(self, mech_context):
        """Create logical port on the fortigate (db update)."""
        LOG.debug("create_port_precommit: called")
        port = mech_context.current
        LOG.debug("create_port_precommit mech_context = %s", mech_context)
        context = mech_context._plugin_context
        namespace = fortinet_db.query_record(context,
                            fortinet_db.Fortinet_ML2_Namespace,
                            tenant_id=port['tenant_id'])
        port_id = port['id']
        subnet_id = port['fixed_ips'][0]['subnet_id']
        ip_address = port['fixed_ips'][0]['ip_address']
        mac = port['mac_address']
        db_subnetv2 = fortinet_db.query_record(context, models_v2.Subnet,
                                             id=subnet_id)
        if port['device_owner'] in ['network:router_gateway']:
            if fortinet_db.query_record(context, ext_db.ExternalNetwork,
                                        network_id=port['network_id']):
                utils.set_ext_gw(self, context, port)
        elif port['device_owner'] in ['compute:nova', 'compute:None', '']:
            # add dhcp related functions
            # '': create port before associate the port with a vm
            utils.add_reservedip(self, context,
                                 port_id=port_id,
                                 subnet_id=subnet_id,
                                 mac=mac,
                                 ip=ip_address,
                                 vdom=namespace.vdom)

        elif port['device_owner'] in ['network:router_interface']:
            if db_subnetv2.cidr:
                cidr = netaddr.IPNetwork(db_subnetv2.cidr)
                subnet = ' '.join([str(cidr.network), str(cidr.netmask)])
                utils.add_fwaddress(self, context,
                                    vdom=namespace.vdom,
                                    name=str(cidr.network),
                                    subnet=subnet)
                addrgrp_name = const.PREFIX['addrgrp'] + namespace.vdom
                utils.add_addrgrp(self, context,
                                  name=addrgrp_name,
                                  vdom=namespace.vdom,
                                  members=[str(cidr.network)])
                utils.add_fwpolicy(self, context,
                                   vdom=namespace.vdom,
                                   srcintf='any',
                                   srcaddr=addrgrp_name,
                                   dstintf='any',
                                   dstaddr=addrgrp_name,
                                   nat='disable')
        return

    @log_helpers.log_method_call
    def create_port_postcommit(self, mech_context):
        """Associate the assigned MAC address to the portprofile."""
        LOG.debug("create_port_postcommit: called")
        context = mech_context._plugin_context
        utils.update_status(self, context, t_consts.TaskStatus.COMPLETED)

    @log_helpers.log_method_call
    def delete_port_postcommit(self, mech_context):
        LOG.debug("delete_port_postcommit: called")
        port = mech_context.current
        context = mech_context._plugin_context
        try:
            port_id = port['id']
            subnet_id = port['fixed_ips'][0]['subnet_id']
            db_subnet = fortinet_db.query_record(context,
                                             fortinet_db.Fortinet_ML2_Subnet,
                                             subnet_id=subnet_id)
            db_subnetv2 = fortinet_db.query_record(context, models_v2.Subnet,
                                                   id=subnet_id)
            if port['device_owner'] in ['network:router_gateway']:
                if fortinet_db.query_record(context, ext_db.ExternalNetwork,
                                            network_id=port['network_id']):
                    #delete ippool and its related firewall policy
                    utils.clr_ext_gw(self, context, port)

            elif port['device_owner'] in ['compute:nova', 'compute:None', '']:
                # delete dhcp related functions
                utils.delete_reservedip(self, context, port_id=port_id)

            elif port['device_owner'] in ['network:router_interface']:
                # add firewall address and address group
                name = const.PREFIX['addrgrp'] + db_subnet.vdom
                member = str(netaddr.IPNetwork(db_subnetv2.cidr).network)
                utils.delete_fwpolicy(self, context,
                                      vdom=db_subnet.vdom,
                                      srcintf='any',
                                      srcaddr=name,
                                      dstintf='any',
                                      dstaddr=name,
                                      nat='disable')
                utils.delete_addrgrp(self, context,
                                     name=name,
                                     vdom=db_subnet.vdom,
                                     members=member.split(' '))
                utils.delete_fwaddress(self, context,
                                       vdom=db_subnet.vdom,
                                       name=member)
        except Exception as e:
            resources.Exinfo(e)
            raise ml2_exc.MechanismDriverError(
                method=sys._getframe().f_code.co_name)

    @log_helpers.log_method_call
    def update_port_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug("update_port_precommit: called")

    @log_helpers.log_method_call
    def update_port_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug("update_port_postcommit: called")

    @log_helpers.log_method_call
    def bind_port(self, context):
        """Marks ports as bound.

        Binds external ports and ports.
        Fabric configuration will occur on the subsequent port update.
        Currently only vlan segments are supported.
        """
        LOG.debug("bind_port() called")
        if (context.current['device_owner'] ==
            l3_constants.DEVICE_OWNER_ROUTER_INTF):
            # check controller to see if the port exists
            # so this driver can be run in parallel with others that add
            # support for external port bindings
            for segment in context.network.network_segments:
                if segment[driver_api.NETWORK_TYPE] == p_const.TYPE_VLAN:
                    context.set_binding(
                        segment[driver_api.ID], portbindings.VIF_TYPE_OVS,
                        {portbindings.CAP_PORT_FILTER: False,
                         portbindings.OVS_HYBRID_PLUG: False})
                    return

        for segment in context.network.network_segments:
            if segment[driver_api.NETWORK_TYPE] == p_const.TYPE_VLAN:
                context.set_binding(
                    segment[driver_api.ID], portbindings.VIF_TYPE_OVS,
                    {portbindings.CAP_PORT_FILTER: False,
                    portbindings.OVS_HYBRID_PLUG: False})
