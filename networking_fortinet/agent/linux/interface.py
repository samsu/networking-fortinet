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
from oslo_config import cfg
from oslo_log import log as logging
import six

from neutron.agent.linux import interface
from neutron.agent.linux import utils
from neutron.common import constants as n_const
from neutron.common import exceptions
from neutron.common import ipv6_utils
from neutron.i18n import _LE, _LI

from networking_fortinet.agent.common import ovs_lib

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
        return dev_name

    def _ovs_add_port(self, bridge, device_name, port_id, mac_address,
                      internal=True):
        attrs = [('external_ids', {'iface-id': port_id,
                                   'iface-status': 'active',
                                   'attached-mac': mac_address})]
        if internal:
            attrs.insert(0, ('type', 'internal'))

        ovs = ovs_lib.FortinetOVSBridge(bridge)
        ovs.set_interface(device_name, *attrs)

    def plug_new(self, network_id, port_id, device_name, mac_address,
                 bridge=None):
        """Plug in the interface."""
        if not bridge:
            bridge = self.conf.ovs_integration_bridge

        self.check_bridge_exists(bridge)
        tap_name = self._get_tap_name(device_name)
        internal = not self.conf.ovs_use_veth
        self._ovs_add_port(bridge, tap_name, port_id, mac_address,
                           internal=internal)

    def unplug(self, device_name, bridge=None, namespace=None, prefix=None):
        """Unplug the interface."""
        if not bridge:
            bridge = self.conf.ovs_integration_bridge

        tap_name = self._get_tap_name(device_name, prefix)
        self.check_bridge_exists(bridge)
        ovs = ovs_lib.FortinetOVSBridge(bridge)

        try:
            ovs.delete_port(tap_name)
            if self.conf.ovs_use_veth:
                device = ip_lib.IPDevice(device_name, namespace=namespace)
                device.link.delete()
                LOG.debug("Unplugged interface '%s'", device_name)
        except RuntimeError:
            LOG.error(_LE("Failed unplugging interface '%s'"),
                      device_name)
