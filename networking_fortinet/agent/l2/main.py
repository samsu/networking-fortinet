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


import sys

from oslo_config import cfg
from oslo_log import log as logging
from neutron.common import config as common_config
from neutron.common import utils as n_utils
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl \
    import br_int
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl \
    import br_phys
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl \
    import br_tun

#from networking_fortinet.agent.l2.openvswitch import br_int
from networking_fortinet.agent.l2.openvswitch import ovs_neutron_agent

LOG = logging.getLogger(__name__)
cfg.CONF.import_group('OVS', 'neutron.plugins.ml2.drivers.openvswitch.agent.'
                      'common.config')
try:
    cls_br_int = br_int.FortinetOVSIntegrationBridge
except AttributeError:
    cls_br_int = br_int.OVSIntegrationBridge

_main_modules = {
    'ovs-ofctl': 'networking_fortinet.agent.l2.main'
}

def init_config():
    pass

def main():
    common_config.init(sys.argv[1:])
    init_config()
    common_config.setup_logging()
    n_utils.log_opt_values(LOG)
    print "## cls_br_int=", cls_br_int
    bridge_classes = {
        #br_int.FortinetOVSIntegrationBridge,
        'br_int': cls_br_int,
        'br_phys': br_phys.OVSPhysicalBridge,
        'br_tun': br_tun.OVSTunnelBridge,
    }
    ovs_neutron_agent.main(bridge_classes)

