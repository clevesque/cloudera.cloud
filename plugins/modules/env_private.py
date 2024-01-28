#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2024 Cloudera, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cloudera.cloud.plugins.module_utils.cdp_common import CdpModule

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: env_private
short_description: Manage CDP Private Cloud Environments
description:
    - Create, update, and delete PvC Environments
    - Note that changing states, in particular, creating a new environment, can take several minutes.
    - Form Factor: Private
author:
  - "Chuck Levesque (clevesque@cloudera.com)"
requirements:
  - cdpy
options:
  environment-name:
    description:
      - The name of the target environment.
      - Must contain only lowercase letters, numbers and hyphens.
    type: str
    required: True
    aliases:
      - name
  address:
    description:
      - The address of the Cloudera Manager managing the Datalake cluster
    type: str
    required: False
    aliases:
      - cm
  user:
    description:
      - User name for accessing the Cloudera Manager
    type: str
    required: False
  authentication-token:
    description:
      - A string (text or json) used to authenticate to the Cloudera Manager
    type: str
    required: False
  cluster-names:
    description:
      - The name of the cluster(s) to use as a Datalake for the environment
    type: list
    required: False
  kube-config:
    description:
      - Name of credentials holding kubeconfig for access to the kubernetes cluster paired with this Environment
    type: str
    required: False
  authentication-token-type:
    description:
      - How to interpret the authentication-token field
    type: str
    required: False
    default: CLEARTEXT_PASSWORD
  namespace-prefix:
    description:
      - Prefix for all namespaces created by Cloudera Data Platform within this cluster
    type: str
    required: False
  domain:
    description:
      - default domain suffix to work workload applications to use
    type: str
    required: False
  platform:
    description:
      - the K8s cluster type used for the environment
    type: str
    required: False
  docker-config-json:
    description:
      - docker pull secrets for the K8s cluster. This is expected to be a docker config json
    type: str
    required: False
  docker-user-pass:
    description:
      - Alternative to dockerConfigJson
    type: dict
    required: False
    suboptions:
      - username:
          type: str
          required: False
      - password:
          type: str
          required: False
      - email:
          type: str
          required: False
      - server:
          type: str
          required: False
  description:
    description:
      - An description of the environment.
    type: str
    required: False
  storage-class:
    description:
      - An existing storage class on this kubernetes cluster. If not specified, the default storage class will be used.
        type: str
    required: False
  state:
    description:
      - The declarative state of the environment
    type: str
    required: False
    default: present
    choices:
      - present
      - absent
  wait:
    description:
      - Flag to enable internal polling to wait for the environment to achieve the declared state.
      - If set to FALSE, the module will return immediately.
    type: bool
    required: False
    default: True
  delay:
    description:
      - The internal polling interval (in seconds) while the module waits for the environment to achieve the declared
        state.
    type: int
    required: False
    default: 15
    aliases:
      - polling_delay
  timeout:
    description:
      - The internal polling timeout (in seconds) while the module waits for the environment to achieve the declared
        state.
    type: int
    required: False
    default: 3600
    aliases:
      - polling_timeout

extends_documentation_fragment:
  - cloudera.cloud.cdp_sdk_options
  - cloudera.cloud.cdp_auth_options
'''

EXAMPLES = r'''


# Create a Private Cloud environment
- cloudera.cloud.env_private:
    environment-name: example-environment
    address: "https://<cm-host>:<cm-port>"
    user:    example-cm-user
    authentication-token: example-cm password
    cluster-names: [ example-basecluster-name1 ]
    state: present

# Delete a Private Cloudera environment
- cloudera.cloud.env_private:
    name: example-module
    state: absent

'''

RETURN = r'''

---

environment:
  description: The information about the Environment
  type: dict
  returned: on success

'''


class Environment_Private(CdpModule):
    def __init__(self, module):
        super(Environment, self).__init__(module)

        self.environment_name = self._get_param('environment_name')
        self.address = self.get_param('address')
        self.authentication_token = self.get_param('authentication_token')
        self.cluster_names = self.get_param('cluster_names')
        self.kube_config = self.get_param('kube_config ')
        self.authentication_token_type = self.get_param('authentication_token_type')
        self.namespace_prefix = self.get_param('namespace_prefix')
        self.domain = self.get_param('domain')
        self.platform = self.get_param('platform')
        self.docker_config_json = self.get_param('docker_config_json')
        self.docker_user_pass = self.get_param('docker_user_pass')
        self.description = self.get_param('description')
        self.storage_class = self.get_param('storage_class')

        self.delay = self._get_param('delay')
        self.timeout = self._get_param('timeout')
        self.wait = self._get_param('wait', False)
        self.changed = None

        # Initialize the return values
        self.environment = dict()

        # Execute logic process
        self.process()

    @CdpModule._Decorators.process_debug
    def process(self):
        existing: object = self.cdpy.environments.describe_environment(self.environment_name)

        if self.state not in ['present']:
            payload = self._configure_payload()

        if not self.module.check_mode:
            self.environment = self.cdpy.environments.create_private_environment(**payload)
            self.changed = True

        if self.wait:
            self.environment = self.cdpy.sdk.wait_for_state(
                describe_func=self.cdpy.environments.describe_environment,
                params=dict(name=self.environment_name),
                state='AVAILABLE',
                delay=self.delay,
                timeout=self.timeout
            )

        # Else create the environment
        elif self.state == 'absent':
            # Warn if attempting to delete an already terminated/terminating environment
            if existing is None:
                return
            else:
                pass
            # If the environment exists
            if not self.wait and (existing['status'] in self.cdpy.sdk.TERMINATION_STATES):
                self.module.warn("Attempting to delete an environment during the termination cycle")
                self.environment = existing
            # Otherwise, delete the environment
            else:
                if not self.module.check_mode:
                    self.cdpy.environments.delete_environment(self.environment_name)
                    self.changed = True

                    if self.wait:
                        self.environment = self.cdpy.sdk.wait_for_state(
                            describe_func=self.cdpy.environments.describe_environment,
                            params=dict(name=self.environment_name),
                            field=None,
                            delay=self.delay,
                            timeout=self.timeout
                        )

        else:
            self.module.fail_json(msg='Invalid state: %s' % self.state)

    def update_credential(self):
        if not self.module.check_mode:
            self.cdpy.sdk.call('environments', 'change_environment_credential',
                               environmentName=self.environment_name, credentialName=self.credential)
        self.environment = self.cdpy.environments.describe_environment(self.environmiment_name)
        self.changed = True

    def _configure_payload(self):
        payload = dict(environmentName=self.name, credentialName=self.credential)

        if self.description is not None:
            payload['description'] = self.description
        return payload


def main():
    module = AnsibleModule(
        argument_spec=CdpModule.argument_spec(
            name=dict(required=True, type='str', aliases=['environment']),
            state=dict(required=False, type='str', choices=['present', 'absent'],
                       default='present'),
            credential=dict(required=False, type='str'),
            description=dict(required=False, type='str', aliases=['desc']),
            force=dict(required=False, type='bool', default=False),
            wait=dict(required=False, type='bool', default=True),
            delay=dict(required=False, type='int', aliases=['polling_delay'], default=15),
            timeout=dict(required=False, type='int', aliases=['polling_timeout'], default=3600),

        ),
        # TODO: Update for Azure
        required_if=[
            ['state', 'present', ('cloud', 'credential'), True],
            ['cloud', 'aws', ('public_key_text', 'public_key_id'), True],
            ['cloud', 'aws', ('network_cidr', 'vpc_id'), True],
            ['cloud', 'aws', ('inbound_cidr', 'default_sg', 'knox_sg'), True]
        ],
        required_by={
            'cloud': ('region', 'credential', 'log_location', 'log_identity'),
        },
        mutually_exclusive=[
            ['network_cidr', 'vpc_id'],
            ['network_cidr', 'subnet_ids'],
            ['public_key_id', 'public_key_text'],
            ['inbound_cidr', 'default_sg'],
            ['inbound_cidr', 'knox_sg']
        ],
        required_together=[
            ['vpc_id', 'subnet_ids'],
            ['default_sg', 'knox_sg']
        ],
        supports_check_mode=True
    )

    result = Environment_Private(module)
    output = dict(changed=result.changed, environment=result.environment)

    if result.debug:
        output.update(sdk_out=result.log_out, sdk_out_lines=result.log_lines)

    module.exit_json(**output)


if __name__ == '__main__':
    main()
