control "V-89625" do
  title "The xinetd service must be disabled if no network services using it
are enabled."
  desc  "The \"xinetd\" service provides a dedicated listener service for some
programs, which is no longer necessary for commonly used network services.
Disabling it ensures that these uncommon services are not running and also
prevents attacks against \"xinetd\" itself."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89625"
  tag "rid": "SV-100275r1_rule"
  tag "stig_id": "VRAU-SL-000515"
  tag "fix_id": "F-96367r1_fix"
  tag "cci": ["CCI-000382"]
  tag "nist": ["CM-7 b", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "If network services are using the \"xinetd\" service, this is
not applicable.

To check that the \"xinetd\" service is disabled in system boot configuration,
run the following command:

# chkconfig \"xinetd\" --list

Output should indicate the \"xinetd\" service has either not been installed or
has been disabled at all run levels as shown in the example below:

xinetd 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify \"xinetd\" is disabled through current
runtime configuration:

# service xinetd status

If the service is disabled, the command will return the following output:

Checking for service xinetd: unused

If the service is running, this is a finding."
  tag "fix": "The \"xinetd\" service can be disabled with the following
command:

# chkconfig xinetd off"

describe service('xinetd') do
  it {should_not be_enabled}
  it {should_not be_running}
end

end

