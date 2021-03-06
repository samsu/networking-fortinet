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

from oslo_log import log as logging

from neutron.agent.l3 import dvr_fip_ns
from neutron.agent.l3 import dvr_snat_ns
from neutron.agent.l3 import namespaces
from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.common import constants as l3_constants
from neutron.i18n import _LE

from networking_fortinet.agent.linux import interface
from networking_fortinet.common import constants as const

LOG = logging.getLogger(__name__)

FTNT_DR = interface.FortinetOVSInterfaceDriver
ENABLE_DVR = l3_constants.L3_AGENT_MODE_DVR

class NamespaceManager(object):

    """Keeps track of namespaces that need to be cleaned up.

    This is a context manager that looks to clean up stale namespaces that
    have not been touched by the end of the "with" statement it is called
    in.  This formalizes the pattern used in the L3 agent which enumerated
    all of the namespaces known to the system before a full sync.  Then,
    after the full sync completed, it cleaned up any that were not touched
    during the sync. The agent and this context manager use method keep_router
    to communicate. In the "with" statement, the agent calls keep_router to
    record the id's of the routers whose namespaces should be preserved.
    Any other router and snat namespace present in the system will be deleted
    by the __exit__ method of this context manager

    This pattern can be more generally applicable to other resources
    besides namespaces in the future because it is idempotent and, as such,
    does not rely on state recorded at runtime in the agent so it handles
    agent restarts gracefully.
    """

    ns_prefix_to_class_map = {
        namespaces.NS_PREFIX: namespaces.RouterNamespace,
        dvr_snat_ns.SNAT_NS_PREFIX: dvr_snat_ns.SnatNamespace,
        dvr_fip_ns.FIP_NS_PREFIX: dvr_fip_ns.FipNamespace,
    }

    def __init__(self, agent_conf, driver, fortigate, clean_stale,
                 metadata_driver=None):
        """Initialize the NamespaceManager.

        :param agent_conf: configuration from l3 agent
        :param driver: to perform operations on devices
        :param clean_stale: Whether to try to clean stale namespaces
        :param metadata_driver: used to cleanup stale metadata proxy processes
        """
        self.agent_conf = agent_conf
        self.driver = driver
        self.fortigate = fortigate
        self._clean_stale = clean_stale
        self.metadata_driver = metadata_driver
        if metadata_driver:
            self.process_monitor = external_process.ProcessMonitor(
                config=agent_conf,
                resource_type='router')

    def __enter__(self):
        self._all_namespaces = set()
        self._ids_to_keep = set()
        if self._clean_stale:
            self._all_namespaces = self.list_all()
        return self

    def __exit__(self, exc_type, value, traceback):
        # TODO(carl) Preserves old behavior of L3 agent where cleaning
        # namespaces was only done once after restart.  Still a good idea?
        if exc_type:
            # An exception occurred in the caller's with statement
            return False
        if not self._clean_stale:
            # No need to cleanup
            return True
        self._clean_stale = False

        for ns in self._all_namespaces:
            router_id, vdom = ns.split('_')
            if router_id in self._ids_to_keep:
                continue
            self._ftnt_cleanup(ns)
            #_ns_prefix, ns_id = self.get_prefix_and_id(ns)
            #if ns_id in self._ids_to_keep:
            #    continue
            #self._cleanup(_ns_prefix, ns_id)
        return True

    def keep_router(self, router_id):
        self._ids_to_keep.add(router_id)

    def keep_ext_net(self, ext_net_id):
        self._ids_to_keep.add(ext_net_id)

    def list_all(self):
        """Get a set of all namespaces on host managed by this manager."""
        try:
            if self.agent_conf.agent_mode == ENABLE_DVR and isinstance(
                    self.driver, FTNT_DR):
                return self.driver.get_namespaces()
            else:
                root_ip = ip_lib.IPWrapper()
                namespaces = root_ip.get_namespaces()
                return set(ns for ns in namespaces if self.is_managed(ns))
        except RuntimeError:
            LOG.exception(_LE('RuntimeError in obtaining namespace list for '
                              'namespace cleanup.'))
            return set()

    def ensure_router_cleanup(self, router_id):
        """Performs cleanup for a router"""
        for ns in self.list_all():
            self._ftnt_cleanup(ns)
            #if ns.endswith(router_id):
                #ns_prefix, ns_id = self.get_prefix_and_id(ns)
                #self._cleanup(ns_prefix, ns_id)

    def _ftnt_cleanup(self, namespace):
        """clean fgt data first, then clean ovs data"""
        ports = self.driver.get_pid_in_namespace(namespace)
        fwpolicy = self.driver.get_fwpolicy(namespace)
        inf_names = self.driver.get_vlan_ports(ports)
        self.fortigate.clean_namespace_trash(namespace, fwpolicy, inf_names)
        self.driver.del_fwpolicy(namespace)
        for port_id in ports:
            self.driver.unplug(const.INTERNAL_DEV_PORT, port_id=port_id,
                               namespace=namespace)
        try:
            self.driver.del_namespace(namespace=namespace)
        #ns = ns_class(ns_id, self.agent_conf, self.driver, use_ipv6=False)
        #try:
        #    if self.metadata_driver:
        #        # cleanup stale metadata proxy processes first
        #        self.metadata_driver.destroy_monitored_metadata_proxy(
        #            self.process_monitor, ns_id, self.agent_conf)
        #    ns.delete()
        except RuntimeError:
            LOG.exception(_LE('Failed to destroy stale namespace %s'),
                          namespace)
