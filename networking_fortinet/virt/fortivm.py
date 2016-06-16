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

from __future__ import absolute_import

import libvirt
import threading

from oslo_config import cfg
from oslo_log import log as logging

from networking_fortinet._i18n import _, _LE
from networking_fortinet.common import constants as const
from networking_fortinet.common import exceptions
from networking_fortinet.virt.libvirt import guest as libvirt_guest

LOG = logging.getLogger(__name__)

CONF = cfg.CONF
CONF.import_group(const.CONF_SECTION, 'networking_fortinet.common.config')


class LibvirtDriver(object):

    def __init__(self, read_only=False):
        self.cfg = getattr(CONF, const.CONF_SECTION, None)
        self.uri = self._uri()
        self._wrapped_conn_lock = threading.Lock()

    def _uri(self):
        uri = self.cfg.libvirt_connection_uri or 'qemu:///system'
        return uri

    def get_guest(self, instance):
        """Retrieve libvirt domain object for an instance.

        :param instance: an nova.objects.Instance object

        :returns: a virt.libvirt.Guest object
        """
        return libvirt_guest.Guest(
            self.get_domain(instance))

    def get_domain(self, instance):
        """Retrieve libvirt domain object for an instance.

        :param instance: an fortivm Instance object

        Attempt to lookup the libvirt domain objects
        corresponding to the Nova instance, based on
        its name. If not found it will raise an
        exception.InstanceNotFound exception. On other
        errors, it will raise a exception.NovaException
        exception.

        :returns: a libvirt.Domain object
        """
        return self._get_domain_by_name(instance.name)

    def _get_domain_by_name(self, instance_name):
        """Retrieve libvirt domain object given an instance name.

        All libvirt error handling should be handled in this method and
        relevant nova exceptions should be raised in response.

        """
        try:
            conn = self.get_connection()
            return conn.lookupByName(instance_name)
        except libvirt.libvirtError as ex:
            error_code = ex.get_error_code()
            if error_code == libvirt.VIR_ERR_NO_DOMAIN:
                raise exceptions.InstanceNotFound(instance_id=instance_name)

            msg = (_('Error from libvirt while looking up %(instance_name)s: '
                     '[Error Code %(error_code)s] %(ex)s') %
                   {'instance_name': instance_name,
                    'error_code': error_code,
                    'ex': ex})
            raise exceptions.FortinetException(msg)

    def _get_connection(self):
        # multiple concurrent connections are protected by _wrapped_conn_lock
        with self._wrapped_conn_lock:
            wrapped_conn = self._wrapped_conn
            if not wrapped_conn or not self._test_connection(wrapped_conn):
                wrapped_conn = self._get_new_connection()

        return wrapped_conn

    @staticmethod
    def _test_connection(conn):
        try:
            conn.getLibVersion()
            return True
        except libvirt.libvirtError as e:
            if (e.get_error_code() in (libvirt.VIR_ERR_SYSTEM_ERROR,
                                       libvirt.VIR_ERR_INTERNAL_ERROR) and
                e.get_error_domain() in (libvirt.VIR_FROM_REMOTE,
                                         libvirt.VIR_FROM_RPC)):
                LOG.debug('Connection to libvirt broke')
                return False
            raise

    def _get_new_connection(self):
        # call with _wrapped_conn_lock held
        LOG.debug('Connecting to libvirt: %s', self._uri)
        wrapped_conn = None

        try:
            wrapped_conn = self._connect(self._uri, self._read_only)
        finally:
            # Enabling the compute service, in case it was disabled
            # since the connection was successful.
            disable_reason = None
            if not wrapped_conn:
                disable_reason = 'Failed to connect to libvirt'

            if self._conn_event_handler is not None:
                self._conn_event_handler(bool(wrapped_conn), disable_reason)

        self._wrapped_conn = wrapped_conn

        try:
            LOG.debug("Registering for lifecycle events %s", self)
            wrapped_conn.domainEventRegisterAny(
                None,
                libvirt.VIR_DOMAIN_EVENT_ID_LIFECYCLE,
                self._event_lifecycle_callback,
                self)
        except Exception as e:
            LOG.warn(_LW("URI %(uri)s does not support events: %(error)s"),
                     {'uri': self._uri, 'error': e})

        try:
            LOG.debug("Registering for connection events: %s", str(self))
            wrapped_conn.registerCloseCallback(self._close_callback, None)
        except (TypeError, AttributeError) as e:
            # NOTE: The registerCloseCallback of python-libvirt 1.0.1+
            # is defined with 3 arguments, and the above registerClose-
            # Callback succeeds. However, the one of python-libvirt 1.0.0
            # is defined with 4 arguments and TypeError happens here.
            # Then python-libvirt 0.9 does not define a method register-
            # CloseCallback.
            LOG.debug("The version of python-libvirt does not support "
                      "registerCloseCallback or is too old: %s", e)
        except libvirt.libvirtError as e:
            LOG.warn(_LW("URI %(uri)s does not support connection"
                         " events: %(error)s"),
                     {'uri': self._uri, 'error': e})

        return wrapped_conn


    def get_connection(self):
        """Returns a connection to the hypervisor

        This method should be used to create and return a well
        configured connection to the hypervisor.

        :returns: a libvirt.virConnect object
        """
        try:
            conn = self._get_connection()
        except libvirt.libvirtError as ex:
            LOG.exception(_LE("Connection to libvirt failed: %s"), ex)
            payload = dict(ip=CONF.my_ip,
                           method='_connect',
                           reason=ex)
            rpc.get_notifier('compute').error(nova_context.get_admin_context(),
                                              'compute.libvirt.error',
                                              payload)
            raise exceptions.HypervisorUnavailable(host=CONF.host)

        return conn





