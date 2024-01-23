#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2023 Cloudera, Inc. All Rights Reserved.
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
from ..module_utils.cdp_common import CdpModule


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
module: private.de
short_description: Enable and Disable CDP Data Engineering Services
description:
    - Enable or Disable CDP Data Engineering Service
author:
  - "Curtis Howard (@curtishoward)"
  - "Alan Silva (@acsjumpi)"
requirements:
  - cdpy
options:
  name:
    description:
      - The name of the CDE Service
    type: str
    required: True
    aliases:
      - name
  environment:
    description:
      - CDP environment where CDE service should be enabled
    type: str
    required: True
    aliases:
      - env
  chart_value_overrides:
    description:
    - Chart overrides for enabling a service
    type: list
    elements: dict
    required: False
    suboptions:
      chart_name:
        description:
          - The key-value pair for the chart_name-override
        type: str
        required: False
  enable_workload_analytics:
    description:
    - If set false, diagnostic information about job and query execution is sent to Cloudera Workload Manager
    type: bool
    required: False
  skip_validation:
    description:
    - Skip Validation check.
    type: bool
    required: False
  tags:
    description:
    - User defined labels that tag all provisioned cloud resources
    type: dict
    required: False
    suboptions:
      key:
        description:
          - The key/value pair for the tag
        type: str
        required: False
  use_ssd:
    description:
    - Instance local storage (SSD) would be used for the workload filesystem (Example - spark local directory). Currently supported only for aws services
    type: bool
    required: False
  force:
    description:
      - Flag to force delete a service even if errors occur during deletion.
    type: bool
    required: False
    default: False
    aliases:
      - force_delete
  state:
    description:
      - The declarative state of the CDE service
    type: str
    required: False
    default: present
    choices:
      - present
      - absent
  wait:
    description:
      - Flag to enable internal polling to wait for the DE Service to achieve the declared state.
      - If set to FALSE, the module will return immediately.
    type: bool
    required: False
    default: True
  delay:
    description:
      - The internal polling interval (in seconds) while the module waits for the DE Service to achieve the declared
        state.
    type: int
    required: False
    default: 60
    aliases:
      - polling_delay
  timeout:
    description:
      - The internal polling timeout (in seconds) while the module waits for the DE Service to achieve the declared
        state.
    type: int
    required: False
    default: 7200
    aliases:
      - polling_timeout
'''

EXAMPLES = r'''
# Create a DE service using defaults for optional parameters and wait for completion
- cloudera.cloud.private.de:
    name: cde-cloudera-deploy-example
    env: cdp-environment-name
    state: present
    wait: yes

# Remove a DE service without waiting
- cloudera.cloud.private.de:
    name: cde-cloudera-deploy-example+
    env: cdp-environment-name
    state: absent
    wait: no
'''

RETURN = r'''
---
service:
  description: DE service description
  type: complex
  returned: always
  contains:
    clusterId:
      description: Cluster Id of the CDE Service.
      returned: always
      type: str
    creatorEmail:
      description: Email Address of the CDE creator.
      returned: always
      type: str
    enablingTime:
      description: Timestamp of service enabling.
      returned: always
      type: str
    environmentName:
      description: CDP Environment Name.
      returned: always
      type: str
    name:
      description: Name of the CDE Service.
      returned: always
      type: str
    status:
      description: Status of the CDE Service.
      returned: always
      type: str
    chartValueOverrides:
      description: Status of the CDE Service.
      returned: always
      type: list
      elements: complex
      contains:
        ChartValueOverridesResponse:
          type: list
          returned: always
          contains:
            chartName:
              description: Name of the chart that has to be overridden.
              returned: always
              type: str
            overrides:
              description: Space separated key value-pairs for overriding chart values (colon separated)
              returned: always
              type: str
    cloudPlatform:
      description: The cloud platform where the CDE service is enabled.
      returned: always
      type: str
    clusterFqdn:
      description: FQDN of the CDE service.
      returned: always
      type: str
    creatorCrn:
      description: CRN of the creator.
      returned: always
      type: str
    dataLakeAtlasUIEndpoint:
      description: Endpoint of Data Lake Atlas.E
      returned: always
      type: str
    dataLakeFileSystems:
      description: The Data lake file system.
      returned: always
      type: str
    environmentCrn:
      description: CRN of the environment.
      returned: always
      type: str
    logLocation:
      description: Location for the log files of jobs.
      returned: always
      type: str
    resources:
      description: Resources details of CDE Service.
      returned: always
      type: complex
      contains:
        ServiceResources:
          description: Object to store resources for a CDE service.
          returned: always
          type: complex
          contains:
            initial_instances:
              description: Initial instances for the CDE service.
              returned: always
              type: str
            initial_spot_instances:
              description: Initial Spot Instances for the CDE Service.
              returned: always
              type: str
            instance_type:
              description: Instance type of the CDE service.
              returned: always
              type: str
            max_instances:
              description: Maximum instances for the CDE service.
              returned: always
              type: str
            max_spot_instances:
              description: Maximum Number of Spot instances.
              returned: always
              type: str
            min_instances:
              description: Minimum Instances for the CDE service.
              returned: always
              type: str
            min_spot_instances:
              description: Minimum number of spot instances for the CDE service.
              returned: always
              type: str
            root_vol_size:
              description: Root Volume Size.
              returned: always
              type: str
    tenantId:
      description: CDP tenant ID.
      returned: always
      type: str
'''

class DEService(CdpModule):
    def __init__(self, module):
        super(DEService, self).__init__(module)

        # Set variables
        self.name = self._get_param('name')
        self.env = self._get_param('environment')

        self.instance_type = 'private'

        self.minimum_instances = 0
        self.maximum_instances = 0
        self.chart_value_overrides = self._get_param('chart_value_overrides')
        self.enable_workload_analytics = self._get_param('enable_workload_analytics')
        self.skip_validation = self._get_param('skip_validation')
        self.tags = self._get_param('tags')
        self.use_ssd = self._get_param('use_ssd')
        self.cpu_requests = self._get_param('cpu_requests')
        self.memory_requests = self._get_param('memory_requests')        
        self.gpu_requests = self._get_param('gpu_requests')
        self.resource_pool = self._get_param('resource_pool') 
        self.nfs_storage_class = self._get_param('nfs_storage_class') 
                   
        self.state = self._get_param('state')
        self.force = self._get_param('force')
        self.wait = self._get_param('wait')
        self.delay = self._get_param('delay')
        self.timeout = self._get_param('timeout')

        # Initialize return values
        self.service = None

        # Initialize cluster (service) ID
        self.cluster_id = None

        # Execute logic process
        self.process()


    @CdpModule._Decorators.process_debug
    def process(self):
        self.cluster_id = self.cdpy.de.get_service_id_by_name(name=self.name, env=self.env)
        initial_desc = self.cdpy.de.describe_service(self.cluster_id) if self.cluster_id else None

        # If a service under the name/env pair was found (excluding disabled services)
        if initial_desc and initial_desc['status']:
            # Disable the Service if expected state is 'absent'
            if self.state == 'absent':
                if self.module.check_mode:
                    self.service = initial_desc
                else:
                    # Service is available - disable it
                    if initial_desc['status'] in self.cdpy.sdk.REMOVABLE_STATES:
                        self.service = self._disable_service()
                    # Service exists but is not in a disable-able state (could be in the process of
                    # provisioning, disabling, or may be in a failed state)
                    else:
                        self.module.warn("DE Service is not in a removable state: %s" %
                                         initial_desc['status'])
                        if self.wait:
                            self.module.warn(
                                "Waiting for DE Service to reach Active or Disabled state")
                            current_desc = self._wait_for_state(self.cdpy.sdk.REMOVABLE_STATES +
                                                                self.cdpy.sdk.STOPPED_STATES)
                            # If we just waited fo the service to be provisioned, then dis-abled it
                            if current_desc['status'] in self.cdpy.sdk.REMOVABLE_STATES:
                                self.service = self._disable_service()
                            else:
                                self.service = current_desc
                                if current_desc['status'] not in self.cdpy.sdk.STOPPED_STATES:
                                    self.module.warn("DE service did not disable successfully")
            elif self.state == 'present':
                # Check the existing configuration and state
                self.module.warn("DE Service already present and configuration validation" +
                                 "and reconciliation is not supported")
                self.service = initial_desc
                if self.wait:
                    current_desc = self._wait_for_state(self.cdpy.sdk.REMOVABLE_STATES +
                                                        self.cdpy.sdk.STOPPED_STATES)
                    # If we just waited for the service to be disabled, then enable it
                    if current_desc['status'] in self.cdpy.sdk.STOPPED_STATES:
                        self.service = self._enable_service()
                    else:
                        self.service = current_desc
                        if current_desc['status'] not in self.cdpy.sdk.REMOVABLE_STATES:
                            self.module.warn("DE service did not enable successfully")
            else:
                self.module.fail_json(
                    msg="State %s is not valid for this module" % self.state)

        # Else if the Service does not exist
        else:
            if self.state == 'absent':
                self.module.log(
                    "DE service %s already absent or terminated in Environment %s" %
                    (self.name, self.env))
            # Create the Service
            elif self.state == 'present':
                if not self.module.check_mode:
                    self.service = self._enable_service()
            else:
                self.module.fail_json(
                    msg="State %s is not valid for this module" % self.state)

    def _enable_service(self):
        result = self.cdpy.de.enable_service(
            name=self.name,
            env=self.env,
            instance_type='private',
            minimum_instances=0,
            maximum_instances=0,
            chart_value_overrides=self.chart_value_overrides,
            enable_workload_analytics=self.enable_workload_analytics,
            skip_validation=self.skip_validation,
            tags=self.tags,
            cpu_requests=self.cpu_requests,
            memory_requests=self.memory_requests,    
            gpu_requests=self.gpu_requests,
            resource_pool=self.resource_pool,
            nfs_storage_class=self.nfs_storage_class
        )
        return_desc = None
        if result and result['clusterId']:
            self.cluster_id = result['clusterId']
            if self.wait:
                return_desc = self._wait_for_state(self.cdpy.sdk.REMOVABLE_STATES)
                if return_desc['status'] not in self.cdpy.sdk.REMOVABLE_STATES:
                    self.module.warn("DE service did not enable successfully")
            else:
                return_desc = result
        else:
            self.module.warn("DE service did not enable successfully")
        return return_desc

    def _disable_service(self):
        self.cdpy.de.disable_service(self.cluster_id)
        if self.wait:
            current_desc = self._wait_for_state(self.cdpy.sdk.STOPPED_STATES)
            if current_desc['status'] not in self.cdpy.sdk.STOPPED_STATES:
                self.module.warn("DE service did not disable successfully")
            return current_desc
        else:
            current_desc = self.cdpy.de.describe_service(self.cluster_id)
            return (current_desc if current_desc not in self.cdpy.sdk.STOPPED_STATES else None)

    def _wait_for_state(self, state):
        return self.cdpy.sdk.wait_for_state(
            describe_func=self.cdpy.de.describe_service,
            params=dict(cluster_id=self.cluster_id),
            field='status', state=state, delay=self.delay,
            timeout=self.timeout
        )

def main():
    module = AnsibleModule(
        argument_spec=CdpModule.argument_spec(
            name=dict(required=True, type='str'),
            environment=dict(required=True, type='str', aliases=['env']),
            chart_value_overrides=dict(required=False, type='list', default=None),
            enable_workload_analytics=dict(required=False, type='bool', default=True),
            skip_validation=dict(required=False, type='bool', default=False),
            tags=dict(required=False, type='dict', default=None),
            cpu_requests=dict(required=False, type='str', default=None),
            gpu_requests=dict(required=False, type='str', default=None),
            resource_pool=dict(required=False, type='str', default=None),
            nfs_storage_class=dict(required=False, type='str', default=None),
            force=dict(required=False, type='bool', default=False, aliases=['force_delete']),
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            wait=dict(required=False, type='bool', default=True),
            delay=dict(required=False, type='int', aliases=['polling_delay'], default=60),
            timeout=dict(required=False, type='int', aliases=['polling_timeout'], default=7200)
        ),
        supports_check_mode=True
    )

    result = DEService(module)
    output = dict(changed=False, service=(result.service if result.service else {}))

    if result.debug:
        output.update(sdk_out=result.log_out, sdk_out_lines=result.log_lines)

    module.exit_json(**output)


if __name__ == '__main__':
    main()
