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
module: drscp_backup
short_description: Create/Delete PrivateCloud On-demand Backup
description:
    - Creates an on-demand backup for the control plane including embedded database, 
    - kubernetes objects, persistent volumes, etc. 
    - Backup requests are processed asynchronously and instantaneously.
    - Form Factors: Private
author:
  - "Chuck Levesque (clevesque@cloudera.com)"
requirements:
  - cdpy
options:
  backup_name:
    description: 
      - Specified name for the backup
    type: str
    required: False
    aliases:
      - name
  backup_crn:
    description:
      - The CRN of the backup
    type: str
    required: False
  item_name:
    description:
      - Name of the potential candidate for backup. It is optional in the case of control plane
    type: str
    required: False
  force:
    description:
      - Flag to force delete a Drscp entity even if errors occur during deletion.
    type: bool
    required: False
    default: False
    aliases:
      - force_delete
  state:
    description:
      - The declarative state of the Drscp service
    type: str
    required: False
    default: present
    choices:
      - present
      - absent
  wait:
    description:
      - Flag to enable internal polling to wait for Drscp to achieve the declared state.
      - If set to FALSE, the module will return immediately.
    type: bool
    required: False
    default: True   
  delay:
    description:
      - The internal polling interval (in seconds) while the module waits for Drscp to achieve the declared
        state.
    type: int
    required: False
    default: 60
    aliases:
      - polling_delay
  timeout:
    description:
      - The internal polling timeout (in seconds) while the module waits for Drscp to achieve the declared
        state.
    type: int
    required: False
    default: 7200
    aliases:
      - polling_timeout
extends_documentation_fragment:
  - cloudera.cloud.cdp_sdk_options
  - cloudera.cloud.cdp_auth_options
'''

EXAMPLES = r'''
# Create a On-demand Backup
- cloudera.cloud.drscp:
    backup_name: cloudera-drscp-example
    state: present
  
# Delete a On-demand Backup History
- cloudera.cloud.drscp:
    backup_crn: cloudera-drscp-crn-example
    state: absent

'''

RETURN = r'''
---

backupCrn:
  description: The CRN of the backup
  returned: always
  type: str

deleteBackupCrn:
  description: The CRN of the deleted backup
  returned: always
  type: str  

'''


class DrscpService(CdpModule):
    def __init__(self, module):
        super(DrscpService, self).__init__(module)
        # Set variables
        self.backup_name = self._get_param('backup_name')
        self.item_name = self._get_param('item_name')
        self.backup_crn = self._get_param('backup_crn')
        self.state = self._get_param('state')
        self.force = self._get_param('force')
        self.wait = self._get_param('wait')
        self.delay = self._get_param('delay')
        self.timeout = self._get_param('timeout')

        # Initialize return values
        self.out_backup_crn = None
        self.delete_backup_crn = None
        self.output = None

        # Execute logic process
        self.process()

    @CdpModule._Decorators.process_debug
    def process(self):
        if self.state == 'present':
            self.out_backup_crn = self._create_backup()
        elif self.state == 'absent':
            self.delete_backup_crn = self._delete_backup()
        else:
            self.module.fail_json(
                msg="State %s is not valid for this module" % self.state)

    def _create_backup(self):
        return self.cdpy.drscp.create_backup(
            backup_name=self.backup_name,
            item_name=self.item_name
        )

    def _delete_backup(self):
        return self.cdpy.drscp.delete_backup(
            backup_crn=self.backup_crn
        )


def main():
    module = AnsibleModule(
        argument_spec=CdpModule.argument_spec(
            backup_name=dict(required=False, type='str'),
            item_name=dict(required=False, type='str'),
            backup_crn=dict(required=False, type='str'),
            force=dict(required=False, type='bool', default=False, aliases=['force_delete']),
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            wait=dict(required=False, type='bool', default=True),
            delay=dict(required=False, type='int', aliases=['polling_delay'], default=60),
            timeout=dict(required=False, type='int', aliases=['polling_timeout'], default=7200)
        ),
        supports_check_mode=True
    )

    result = DrscpService(module)
    output = dict(changed=False, out_backup_crn=(result.backup_crn if result.backup_crn else {}))

    if result.debug:
        output.update(sdk_out=result.log_out, sdk_out_lines=result.log_lines)

    module.exit_json(**output)


if __name__ == '__main__':
    main()
