# Copyright 2016 Fortinet Inc.
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

from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl \
    import br_tun


class FortinetOVSTunnelBridge(br_tun.OVSTunnelBridge):
    """Fortinetopenvswitch agent tunnel bridge specific logic."""

    def install_dvr_process(self, vlan_tag, vif_mac, dvr_mac_address):
        self.add_flow(table=self.dvr_process_table_id,
                      priority=3,
                      dl_vlan=vlan_tag,
                      proto='arp',
                      dl_src=vif_mac,
                      actions="resubmit(,%s)" % self.dvr_process_next_table_id)
        super(FortinetOVSTunnelBridge, self).install_dvr_process(
            vlan_tag, vif_mac, dvr_mac_address)
