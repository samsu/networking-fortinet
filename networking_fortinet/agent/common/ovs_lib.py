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
import ast
import unicodedata

from neutron.agent.ovsdb import impl_vsctl
from neutron.agent.common import ovs_lib
from oslo_serialization import jsonutils

from networking_fortinet._i18n import _LI, _LW
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

    @staticmethod
    def _format_attr(attrs):
        def _fmt_attr(attr):
            if isinstance(attr, dict):
                fmt_attr = {}
                for key, val in attr.iteritems():
                    try:
                        if isinstance(key, unicode):
                            key = str(key)
                        fmt_attr[key] = ast.literal_eval(val)
                    except (SyntaxError, ValueError):
                        fmt_attr[key] = val
                return fmt_attr
            return attr

        if isinstance(attrs, list):
            fmt_attrs = []
            for _attr in attrs:
                if isinstance(_attr, dict):
                    _attr = {k: _fmt_attr(v) for k, v in _attr.iteritems()}
                fmt_attrs.append(_attr)
            return fmt_attrs
        else:
            return _fmt_attr(attrs)

    @staticmethod
    def _ftnt_columns(columns):
        new_columns = copy.copy(columns)
        if isinstance(columns, list):
            if 'tag' in columns:
                new_columns.remove('tag')
                new_columns.append('trunks')
        return new_columns

    def _add_attr(self, cur_attr, add_attr):
        LOG.debug("## _add_attr() called, cur_attr=%(cur_attr)s, "
                  "add_attr=%(add_attr)s",
                  {'cur_attr': cur_attr, 'add_attr': add_attr})
        if not add_attr:
            return
        if isinstance(add_attr, dict):
            for field, value in add_attr.iteritems():
                cur_value = cur_attr.get(field, None)
                if isinstance(value, dict) and isinstance(cur_value, dict):
                    if all((k in value and cur_value.get(k, None) == v) \
                           for k, v in value.iteritems()):
                        return
                    else:
                        self._add_attr(cur_value, value)
                elif isinstance(value, (set, list)) or \
                        isinstance(cur_value, list):
                    if isinstance(cur_value, int):
                        cur_value = str(cur_value)
                    if not isinstance(value, (set, list)):
                        value = [value]
                    if not isinstance(cur_value, (set, list)):
                        cur_value = [cur_value]
                    cur_attr[field] = list(set(value) | set(cur_value))

        elif isinstance(add_attr, (list, set)):
            cur_attr = set(add_attr) | set(cur_attr) \
                if isinstance(cur_attr, list) else add_attr
            cur_attr = list(cur_attr)

        elif isinstance(add_attr, (str, int)):
            cur_attr = add_attr

        elif isinstance(add_attr, (str, int, unicode)):
            if isinstance(cur_attr, dict):
                cur_attr.setdefault(add_attr, None)
            elif (isinstance(cur_attr, (list, set)) and
                  add_attr not in cur_attr):
                cur_attr.append(str(add_attr))
                cur_attr = [str(element) for element in cur_attr]
            elif isinstance(cur_attr, (str, int, unicode)):
                cur_attr = add_attr
        return cur_attr

    def _del_attr(self, cur_attr, del_attr):
        if not cur_attr:
            return

        for field, value in del_attr.iteritems():
            cur_value =cur_attr.get(field, None)
            if not cur_value:
                continue
            if not value:
                cur_attr[field] = None

            elif isinstance(value, dict):
                self._del_attr(cur_value, value)

            elif isinstance(value, (list, set)):

                if isinstance(cur_value, int):
                    cur_value = [str(cur_value)]
                cur_value = list(set(cur_value) - set(value))

            elif isinstance(value, (str, int, unicode)):
                if isinstance(cur_value, dict):
                        cur_value.pop(value, None)
                elif isinstance(cur_value, (list, set)) and value in cur_value:
                    cur_value.remove(value)
                    cur_value = [str(element) for element in cur_value]
                elif cur_value == value:
                    cur_value = None
            import ipdb;ipdb.set_trace()
            if cur_value is None:
                cur_attr.pop(field, None)
            else:
                cur_attr[field] = cur_value

    def update_attributes(self, cur_attrs, interface_attr_tuples):
        if not cur_attrs:
            return interface_attr_tuples
        new_attrs = copy.deepcopy(cur_attrs[0])
        added_attrs = dict(interface_attr_tuples)
        for col, attr in added_attrs.iteritems():
            # col is the ovs table interface fields, attr is the field's value
            new_attr = self._format_attr(new_attrs[col])
            for ext_k, ext_v in attr.iteritems():
                if isinstance(ext_v, dict):
                    if isinstance(new_attr.get(ext_k, None), dict):
                        new_attr[ext_k].update(ext_v)
                    else:
                        new_attr[ext_k] = ext_v
                elif isinstance(ext_v, set):
                    new_attr[ext_k] = ext_v | set(new_attr.get(ext_k)) \
                        if isinstance(new_attr.get(ext_k, None),
                                      list) else ext_v
                    new_attr[ext_k] = list(new_attr[ext_k])
                else:
                    new_attr[ext_k] = ext_v
            new_attrs[col] = new_attr
        return tuple(new_attrs.items())

    def set_db_attribute(self, table_name, record, column, value,
                         check_error=False, log_errors=True):
        LOG.debug("## set_db_attribute() called, table_name = %(table_name)s,"
                  "record = %(record)s, column=%(col)s, value=%(val)s",
                  {'table_name': table_name, 'record': record,
                   'col': column, 'val': value})
        if not value:
            return self.clear_db_attribute(table_name, record, column)

        if record in consts.FTNT_PORTS:
            cur_attrs = self.db_get_val(table_name, record, column,
                                        check_error=check_error,
                                        log_errors=log_errors)
            cur_attrs = self._format_attr(cur_attrs)
            value = self._add_attr(cur_attrs, value)
            '''
            if isinstance(value, dict) and isinstance(cur_attrs, dict):
                if all((k in value and cur_attrs.get(k, None) == v) for k, v in
                       value.iteritems()):
                    return
                else:
                    value.update(cur_attrs)
            elif isinstance(value, list):
                if isinstance(cur_attrs, int):
                    cur_attrs = str(cur_attrs)
                value = list(set(value) | set(cur_attrs))
            '''
        super(FortinetOVSBridge, self).set_db_attribute(
            table_name, record, column, value, check_error=check_error,
            log_errors=log_errors)

    def del_db_attributes(self, table_name, record, *interface_attr_tuples):
        LOG.debug("## del_db_attribute() called, table_name = %(table_name)s,"
                  "record = %(record)s, interface_attr_tuples=%(attrs)s",
                  {'table_name': table_name, 'record': record,
                   'attrs': interface_attr_tuples})
        if record not in consts.FTNT_PORTS:
            return
        del_attrs = dict(interface_attr_tuples)
        columns = [attr[0] for attr in interface_attr_tuples]
        cur_attrs = self._format_attr(
            self.get_ports_attributes(table_name, columns=columns,
                                      ports=[record]))
        cur_attrs = cur_attrs[0]
        for column, value in del_attrs.iteritems():
            # column is the ovs table interface field need to be deleted, and
            # value is the field's value, if it is a dict or list, then need
            # to find the sub attribute in the value, and handle the deletion.
            # e.g. column is 'external_ids', value is a dict.
            if not value:
                self.clear_db_attribute(table_name, record, column)
            cur_attr =cur_attrs.get(column, None)
            self._del_attr(cur_attr, value)
            # it is better to clear db column when no cur_attr left, however
            # the 'other_config' doesn't support 'set'(like append), have to
            # clear it's exist value then set the new value.
            if 'other_config' == column:
                self.clear_db_attribute(table_name, record, column)
            if cur_attr:
                super(FortinetOVSBridge, self).set_db_attribute(
                    table_name, record, column, cur_attr)
            else:
                self.clear_db_attribute(table_name, record, column)

    def check_attributes(self, cur_attrs, interface_attr_tuples):
        if not cur_attrs:
            return False
        new_attrs = cur_attrs[0]
        chk_attrs = dict(interface_attr_tuples)
        for col, attr in chk_attrs.iteritems():
            # col is the ovs table interface fields, attr is the field's value
            new_attr = self._format_attr(new_attrs[col])
            for ext_k, ext_v in attr.iteritems():
                if isinstance(ext_v, dict) and set(ext_v.items()).issubset(
                        set(new_attr[ext_k].items())):
                    return True
                elif isinstance(ext_v, set) and ext_v.issubset(
                        set(new_attr.get(ext_k))):
                    return True
                elif new_attr[ext_k] == ext_v:
                    return True
        return False

    def delete_attributes(self, cur_attrs, interface_attr_tuples,
                          namespace=None):
        if not cur_attrs:
            return cur_attrs

        new_attrs = copy.deepcopy(cur_attrs[0])
        del_attrs = dict(interface_attr_tuples)
        for col, attr in del_attrs.iteritems():
            # col is the ovs table interface fields, attr is the field's value
            new_attr = self._format_attr(new_attrs[col])
            if col in ['external_ids']:
                id = 'iface-id'
                if isinstance(attr, dict) and id in attr.keys():
                    v = attr[id]
                    v = v.pop() if isinstance(v, set) else v
                    if isinstance(new_attr[id], list) and v in new_attr[id]:
                        new_attr[id].remove(v)
                        for key in ['iface-status']:
                            if isinstance(new_attr[key], dict):
                                new_attr[key].pop(v, None)

        return tuple(new_attrs.items())

    def set_interface_attr(self, port_name, *interface_attr_tuples):
        """Replace existing port attributes, and configure port interface."""
        LOG.debug("## set_interface_attr() called, port_name = %(port_name)s,"
                  "attrs = %(attrs)s",
                  {'port_name': port_name, 'attrs': interface_attr_tuples})
        columns = [attr[0] for attr in interface_attr_tuples]
        # The neutron ovs.lib name ports related functions to operate
        # the ovs table 'interface'
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

    def chk_interface_attr(self, port_name, *interface_attr_tuples):
        """
        :param port_name:
        :param interface_attr_tuples:
         [('external_ids', {'iface-id': set([port_id])})]
        :return:
        """
        LOG.debug("## chk_interface_attr() called, port_name = %(port_name)s,"
                  "attrs = %(attrs)s",
                  {'port_name': port_name, 'attrs': interface_attr_tuples})
        columns = [attr[0] for attr in interface_attr_tuples]
        cur_attrs = self.get_ports_attributes('Interface', columns=columns,
                                              ports=[port_name],
                                              if_exists=True)
        return self.check_attributes(cur_attrs, interface_attr_tuples)

    def del_interface_attr(self, port_name, *interface_attr_tuples):
        """delete existing port attributes, and configure port interface."""
        LOG.debug("## del_interface_attr() called, port_name = %(port_name)s,"
                  "attrs = %(attrs)s",
                  {'port_name': port_name, 'attrs': interface_attr_tuples})
        columns = [attr[0] for attr in interface_attr_tuples]
        # The neutron ovs.lib name 'ports' related functions to operate
        # the ovs table 'interface'
        cur_attrs = self.get_ports_attributes('Interface', columns=columns,
                                              ports=[port_name],
                                              if_exists=True)
        new_attrs = self.delete_attributes(cur_attrs, interface_attr_tuples,
                                           namespace=namespace)
        LOG.debug("### cur_attrs = %(cur_attrs)s, new_attrs = %(new_attrs)s",
                  {'cur_attrs': cur_attrs, 'new_attrs': new_attrs})
        with self.ovsdb.transaction() as txn:
            if interface_attr_tuples:
                txn.add(self.ovsdb.db_set('Interface', port_name, *new_attrs))
        self.get_port_ofport(port_name)

    def get_ports_attributes(self, table, columns=None, ports=None,
                             check_error=True, log_errors=True,
                             if_exists=False):
        port_names = ports or self.get_port_name_list()
        if not port_names:
            return []
        ftnt_port_names = [name for name in consts.FTNT_PORTS if
                           name in port_names]
        port_names = set(port_names) - set(ftnt_port_names)
        attrs = []
        if port_names:
            attrs = super(FortinetOVSBridge, self).get_ports_attributes(
                table, columns=columns, ports=port_names,
                check_error=check_error, log_errors=log_errors,
                if_exists=if_exists)
        if ftnt_port_names:
            attrs += super(FortinetOVSBridge, self).get_ports_attributes(
                table, columns=self._ftnt_columns(columns),
                ports=ftnt_port_names, check_error=check_error,
                log_errors=log_errors, if_exists=if_exists)
        LOG.debug("### get_ports_attributes() attrs=%(attrs)s",
                  {'attrs': attrs})
        return self._format_attr(attrs)

    def portid_from_external_ids(self, external_ids):
        external_ids = self._format_attr(external_ids)
        return super(FortinetOVSBridge, self).portid_from_external_ids(
            external_ids)

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
                    port_id = set(port_id) if isinstance(port_id, list) \
                        else set([port_id])
                    edge_ports |= port_id
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
        #return self.get_fortigate_port_tags_dict(
        #    {p['name']: p['tag'] for p in results if
        #     p['name'] not in consts.FTNT_PORTS})
        LOG.debug("### results = %(results)s", {'results': results})
        return {p['name']: p['tag'] if p['name'] not in consts.FTNT_PORTS
                else p['trunks'] for p in results}

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
        by_id = {}
        for x in interface_info:
            external_ids = self._format_attr(x['external_ids'])
            if x['name'] in consts.FTNT_PORTS and \
                    isinstance(external_ids.get('iface-id'), list):
                if_ids = set(external_ids.get('iface-id'))
                by_id.update({if_id: x for if_id in if_ids})
            elif x['name'] not in consts.FTNT_PORTS:
                by_id.update({external_ids.get('iface-id'): x})
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
            mac = pinfo['external_ids'].get('attached-mac')
            result[port_id] = ovs_lib.VifPort(pinfo['name'], pinfo['ofport'],
                                      port_id, mac, self)
        return result

    def get_vif_port_by_id(self, port_id):
        ports = self.ovsdb.db_find(
            'Interface', ('external_ids', '=', {'iface-id': port_id}),
            ('external_ids', '!=', {'attached-mac': ''}),
            columns=['external_ids', 'name', 'ofport']).execute()
        for port in ports:
            if self.br_name != self.get_bridge_for_iface(port['name']):
                continue
            if not self._check_ofport(port_id, port):
                continue
            mac = port['external_ids'].get('attached-mac')
            return ovs_lib.VifPort(port['name'], port['ofport'],
                                   port_id, mac, self)

        #import ipdb;ipdb.set_trace()
        LOG.info(_LI("Port %(port_id)s not present in bridge %(br_name)s"),
                 {'port_id': port_id, 'br_name': self.br_name})

"""
    def get_vif_ports(self):
        edge_ports = []
        port_info = self.get_ports_attributes(
            'Interface', columns=['name', 'external_ids', 'ofport'],
            if_exists=True)
        for port in port_info:
            name = port['name']
            external_ids = self._format_attr(port['external_ids'])
            ofport = port['ofport']
            if "iface-id" in external_ids and "attached-mac" in external_ids:
                if isinstance(external_ids['iface-id'], list):
                    for id in external_ids['iface-id']:
                        p = ovs_lib.VifPort(name, ofport, id,
                                            external_ids['attached-mac'], self)
                        edge_ports.append(p)
                else:
                    p = ovs_lib.VifPort(name, ofport, external_ids['iface-id'],
                                        external_ids['attached-mac'], self)
                    edge_ports.append(p)
            elif ("xs-vif-uuid" in external_ids and
                  "attached-mac" in external_ids):
                # if this is a xenserver and iface-id is not automatically
                # synced to OVS from XAPI, we grab it from XAPI directly
                iface_id = self.get_xapi_iface_id(external_ids['xs-vif-uuid'])
                p = ovs_lib.VifPort(name, ofport, iface_id,
                                    external_ids['attached-mac'], self)
                edge_ports.append(p)

        return edge_ports
"""

