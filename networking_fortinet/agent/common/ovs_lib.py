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

from neutron.agent.ovsdb import impl_vsctl
from neutron.agent.common import ovs_lib
from oslo_serialization import jsonutils


class FortinetOVSBridge(ovs_lib.OVSBridge):
    def set_port(self, port, **kwargs):
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

    def set_interface(self, port_name, *interface_attr_tuples):
        """Replace existing port attributes, and configure port interface."""
        with self.ovsdb.transaction() as txn:
            if interface_attr_tuples:
                txn.add(self.ovsdb.db_set('Interface', port_name,
                                          *interface_attr_tuples))
        self.get_port_ofport(port_name)
