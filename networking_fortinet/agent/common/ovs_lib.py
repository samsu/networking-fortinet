# Copyright 2016 Fortinet, Inc.
#
# All Rights Reserved
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

import copy

from neutron.agent.ovsdb import impl_vsctl
from neutron.agent.common import ovs_lib
from oslo_serialization import jsonutils

from networking_fortinet._i18n import _LW
from networking_fortinet.common import constants as consts

# Default timeout for ovs-vsctl command
DEFAULT_OVS_VSCTL_TIMEOUT = ovs_lib.DEFAULT_OVS_VSCTL_TIMEOUT

# Special return value for an invalid OVS ofport
INVALID_OFPORT = ovs_lib.INVALID_OFPORT
UNASSIGNED_OFPORT = ovs_lib.UNASSIGNED_OFPORT

# OVS bridge fail modes
FAILMODE_SECURE = ovs_lib.FAILMODE_SECURE
FAILMODE_STANDALONE = ovs_lib.FAILMODE_STANDALONE

INTERNAL_DEV_PORT = consts.INTERNAL_DEV_PORT
EXTERNAL_DEV_PORT = consts.EXTERNAL_DEV_PORT
FTNT_PORTS = consts.FTNT_PORTS

LOG = ovs_lib.LOG

class FortinetOVSBridge(ovs_lib.OVSBridge):
    """ FortinetOVSBridge class
    """
    def set_port(self, port, **kwargs):
        LOG.debug("## set_port() called, port = %(port)s, kwargs = %(kwargs)s",
                  {'port': port, 'kwargs': kwargs})
        args = ['port', port]
        opts = None
        if kwargs:
            for k, v in kwargs.iteritems():
                args.append("%(key)s=%(val)s" % {'key': k, 'val': v})
        with self.ovsdb.transaction() as txn:
            txn.add(
                impl_vsctl.BaseCommand(self.ovsdb.context, 'set', opts, args))
        fields = tuple(key for key in kwargs)
        return self.list_port(port, *fields)

    def list_port(self, port, *fields):
        """
        :param port:
        :param fields:
        :return:
        examples:
        1) ovs.list_port(FGT_INT_PORT, 'trunks')
        #return {'trunks': set([1, 5])}
        2) ovs.list_port(FGT_INT_PORT, 'name', 'trunks')
        #return {'trunks': set([1, 5]), 'name': u'fgt-int-port'}
        """
        args = ['port', port]
        opts = None
        with self.ovsdb.transaction() as txn:
            res = txn.add(impl_vsctl.MultiLineCommand(self.ovsdb.context,
                                                      'list', opts, args))
        res = jsonutils.loads(res.result.pop())
        for k, v in res.iteritems():
            while isinstance(v, (list, tuple)) and 1 == len(v):
                v = v.pop()
            res[k] = v
        keys = res['headings']
        vals = res['data']
        for idx in range(len(vals)):
            if isinstance(vals[idx], (list, tuple)):
                vals[idx] = set(vals[idx][1]) if 'set' == vals[idx][0] \
                    else vals[idx][1]
        res = dict(zip(keys, vals))
        if fields:
            ret_keys = list(set(fields) & set(keys))
            return {key: res[key] for key in ret_keys}
        return res

    def update_attributes(self, cur_attrs, interface_attr_tuples):
        if not cur_attrs:
            return interface_attr_tuples

        new_attrs = copy.deepcopy(cur_attrs[0])
        added_attrs = dict(interface_attr_tuples)
        for attr in added_attrs:
            # k is the column name, v is the column value
            import ipdb;ipdb.set_trace()
            for ext_k, ext_v in attr.iteritems():
                if isinstance(ext_v, dict):
                    for int_k, int_v in ext_v.iteritems():
                        if isinstance(int_v, dict):
                            new_attrs[ext_k][int_k].update(int_v)
                        elif isinstance(int_v, set):
                            new_attrs[ext_k][int_k] |= int_v
                        else:
                            new_attrs[ext_k][int_k] = int_v
                elif isinstance(ext_v, set):
                    new_attrs[ext_k] = ext_v | set([added_attrs[ext_k]])
                else:
                    new_attrs[ext_k] = added_attrs[ext_k]
        return tuple(new_attrs.items())

    def set_interface(self, port_name, *interface_attr_tuples):
        """Replace existing port attributes, and configure port interface."""
        LOG.debug("### set_interface() called, port_name = %(port_name)s, "
                  "attrs = %(attrs)s",
                  {'port_name': port_name, 'attrs': interface_attr_tuples})
        columns = [attr[0] for attr in interface_attr_tuples]
        cur_attrs = self.get_ports_attributes('Interface', columns=columns,
                                              ports=[port_name],
                                              if_exists=True)
        new_attrs = self.update_attributes(cur_attrs, interface_attr_tuples)
        LOG.debug("### cur_attrs = %(cur_attrs)s, new_attrs = %(new_attrs)s",
                  {'cur_attrs': cur_attrs, 'new_attrs': new_attrs})
        with self.ovsdb.transaction() as txn:
            if interface_attr_tuples:
                txn.add(self.ovsdb.db_set('Interface', port_name, *new_attrs))
        self.get_port_ofport(port_name)

    def get_vif_port_set(self):
        LOG.debug("### get_vif_port_set() called")
        print "### get_vif_port_set() called"
        edge_ports = set()
        results = self.get_ports_attributes(
            'Interface', columns=['name', 'external_ids', 'ofport'],
            if_exists=True)
        for result in results:
            if result['ofport'] == UNASSIGNED_OFPORT:
                LOG.warn(_LW("Found not yet ready openvswitch port: %s"),
                         result['name'])
            elif result['ofport'] == INVALID_OFPORT:
                LOG.warn(_LW("Found failed openvswitch port: %s"),
                         result['name'])
            elif 'attached-mac' in result['external_ids']:
                port_id = self.portid_from_external_ids(result['external_ids'])
                if port_id:
                    edge_ports.add(port_id)
        return edge_ports

    def get_port_tag_dict(self):
        """Get a dict of port names and associated vlan tags.

        e.g. the returned dict is of the following form::

            {u'int-br-eth2': [],
             u'patch-tun': [],
             u'qr-76d9e6b6-21': 1,
             u'tapce5318ff-78': 1,
             u'tape1400310-e6': 1}

        The TAG ID is only available in the "Port" table and is not available
        in the "Interface" table queried by the get_vif_port_set() method.

        """
        LOG.debug("### get_port_tag_dict() called")
        results = self.get_ports_attributes(
            'Port', columns=['name', 'tag'], if_exists=True)
        return self.get_fortigate_port_tags_dict(
            {p['name']: p['tag'] for p in results})

    def get_fortigate_port_tags_dict(self, port_tags):
        """ :return the turnks for fortigate ports
        :param port_tags:
        e.g.
            {u'patch-tun': [],
            u'qvoa657dec0-e7': 2,
            u'fgt-int-port': [],
            u'qvo93095522-ab': 1}
        :return:
        """
        # get port_tags like [{u'trunks': [1, 3], u'name': u'fgt-int-port'}]
        results = self.get_ports_attributes('Port', columns=['name', 'trunks'],
                                            ports=FTNT_PORTS, if_exists=True)
        fgt_port_tags = {p['name']: p['trunks'] for p in results}
        port_tags.update(fgt_port_tags)
        return port_tags

    def get_vifs_by_ids(self, port_ids):
        interface_info = self.get_ports_attributes(
            "Interface", columns=["name", "external_ids", "ofport"],
            if_exists=True)
        by_id = {x['external_ids'].get('iface-id'): x for x in interface_info}
        result = {}
        for port_id in port_ids:
            result[port_id] = None
            if port_id not in by_id:
                LOG.info(_LI("Port %(port_id)s not present in bridge "
                             "%(br_name)s"),
                         {'port_id': port_id, 'br_name': self.br_name})
                continue
            pinfo = by_id[port_id]
            if not self._check_ofport(port_id, pinfo):
                continue
            if pinfo['name'] in FTNT_PORTS:
                mac = consts.FTNT_INT_PORT_MAC
            else:
                mac = pinfo['external_ids'].get('attached-mac')
            result[port_id] = ovs_lib.VifPort(pinfo['name'], pinfo['ofport'],
                                              port_id, mac, self)
        return result
