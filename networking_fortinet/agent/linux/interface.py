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
#

import abc
import netaddr
import six

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import uuidutils

from neutron.agent.linux import interface
from neutron.agent.linux import utils
from neutron.common import constants as n_const
from neutron.common import exceptions
from neutron.common import ipv6_utils
from neutron.i18n import _LE, _LI

from networking_fortinet.agent.common import ovs_lib
from networking_fortinet.common import constants as consts

LOG = logging.getLogger(__name__)

OPTS = [
    cfg.StrOpt('ovs_integration_bridge',
               default='br-int',
               help=_('Name of Open vSwitch bridge to use')),
    cfg.BoolOpt('ovs_use_veth',
                default=False,
                help=_('Uses veth for an interface or not')),
    cfg.IntOpt('network_device_mtu',
               help=_('MTU setting for device.')),
]

INTERNAL_DEV_PORT = consts.INTERNAL_DEV_PORT
EXTERNAL_DEV_PORT = consts.EXTERNAL_DEV_PORT
FTNT_PORTS = consts.FTNT_PORTS


class FortinetOVSInterfaceDriver(interface.OVSInterfaceDriver):
    """Driver for creating an internal interface on an OVS bridge."""

    DEV_NAME_PREFIX = n_const.TAP_DEVICE_PREFIX

    def __init__(self, conf):
        super(FortinetOVSInterfaceDriver, self).__init__(conf)
        if self.conf.ovs_use_veth:
            self.DEV_NAME_PREFIX = 'ns-'

    def _get_tap_name(self, dev_name, prefix=None):
        if self.conf.ovs_use_veth:
            dev_name = dev_name.replace(prefix or self.DEV_NAME_PREFIX,
                                        n_const.TAP_DEVICE_PREFIX)
        #if uuidutils.is_uuid_like(dev_name):
        #    if self._ovs_chk_port(None, dev_name, consts.INTERNAL_DEV_PORT):
        #        return consts.INTERNAL_DEV_PORT
        return dev_name

    def _ovs_set_port(self, bridge, device_name, port_id, mac_address,
                      namespace=None, internal=True):
        attrs = [('external_ids',
                  {'iface-id': set([port_id]),
                   'iface-status': {port_id: 'active'},
                   'attached-mac': mac_address,
                   'namespaces': {namespace: [port_id]}
                   })]
        if internal:
            attrs.insert(0, ('type', 'internal'))

        ovs = ovs_lib.FortinetOVSBridge(bridge)
        ovs.set_interface_attr(device_name, *attrs)

    def init_router_port(self, device_name, ip_cidrs, namespace,
                         preserve_ips=None, gateway_ips=None,
                         extra_subnets=None, enable_ra_on_gw=False,
                         clean_connections=False):
        if device_name not in consts.FTNT_PORTS:
            super(FortinetOVSInterfaceDriver, self).init_router_port(
                device_name, ip_cidrs, namespace,
                preserve_ips=preserve_ips,
                gateway_ips=gateway_ips,
                extra_subnets=extra_subnets,
                enable_ra_on_gw=enable_ra_on_gw,
                clean_connections=clean_connections)

    def _ovs_del_port(self, bridge, device_name, port_id, namespace=None):
        if not bridge:
            bridge = self.conf.ovs_integration_bridge
        attrs = [('external_ids',
                  {'iface-id': port_id,
                   'iface-status': port_id,
                   'namespaces': {namespace: port_id}
                   })]
        ovs = ovs_lib.FortinetOVSBridge(bridge)
        ovs.del_db_attributes('Interface', device_name, *attrs)
        #ovs.del_interface_attr(device_name, namespace=namespace, *attrs)

    def _ovs_chk_port(self, bridge, port_id, device_name=None):
        if not bridge:
            bridge = self.conf.ovs_integration_bridge
        if not device_name:
            device_name = consts.INTERNAL_DEV_PORT
        attrs = [('external_ids', {'iface-id': set([port_id])})]
        ovs = ovs_lib.FortinetOVSBridge(bridge)
        return ovs.chk_interface_attr(device_name, *attrs)

    def get_associated_pid(self, device_name, bridge=None):
        if not bridge:
            bridge = self.conf.ovs_integration_bridge
        if not device_name:
            device_name = consts.INTERNAL_DEV_PORT
        ovs = ovs_lib.FortinetOVSBridge(bridge)
        attrs = ovs.get_ports_attributes('Interface',
                                         columns=['external_ids'],
                                         ports=[device_name])
        external_ids = attrs[0]['external_ids']
        return ovs.portid_from_external_ids(external_ids)

    def plug_new(self, network_id, port_id, device_name, mac_address,
                 bridge=None, namespace=None, prefix=None):
        """Plug in the interface."""
        if not bridge:
            bridge = self.conf.ovs_integration_bridge

        self.check_bridge_exists(bridge)
        tap_name = self._get_tap_name(device_name)
        if tap_name in FTNT_PORTS:
            self._ovs_set_port(bridge, tap_name, port_id, mac_address,
                               namespace=namespace, internal=False)
        else:
            super(FortinetOVSInterfaceDriver,
                  self).plug_new(network_id, port_id, device_name, mac_address,
                                 bridge=bridge,
                                 namespace=namespace,
                                 prefix=prefix)

    def unplug(self, device_name, port_id=None, bridge=None, namespace=None,
               prefix=None):
        """Unplug the interface."""
        tap_name = self._get_tap_name(device_name, prefix)
        LOG.debug("## Unplugged interface '%s'", tap_name)
        if tap_name in FTNT_PORTS and port_id:
            ## device_name is the portid
            self._ovs_del_port(bridge, device_name, port_id,
                               namespace=namespace)
        else:
            super(FortinetOVSInterfaceDriver, self).unplug(device_name,
                                                           bridge=bridge,
                                                           namespace=namespace,
                                                           prefix=prefix)
