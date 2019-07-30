control "V-89699" do
  title "The SLES for vRealize must disable account identifiers of individuals
and roles (such as root) after 35 days of inactivity after password expiration."
  desc  "Inactive identifiers pose a risk to systems and applications because
attackers may exploit an inactive identifier and potentially obtain undetected
access to the system. Owners of inactive accounts will not notice if
unauthorized access to their user account has been obtained.

    Operating systems need to track periods of inactivity and disable
application identifiers after 35 days of inactivity.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000118-GPOS-00060"
  tag "gid": "V-89699"
  tag "rid": "SV-100349r1_rule"
  tag "stig_id": "VRAU-SL-000725"
  tag "fix_id": "F-96441r1_fix"
  tag "cci": ["CCI-000795"]
  tag "nist": ["IA-4 e", "Rev_4"]
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
  tag "check": "Verify the SLES for vRealize disables account identifiers after
\"35\" days of inactivity after the password expiration, by performing the
following commands:

# grep \"INACTIVE\" /etc/default/useradd

The output must indicate the \"INACTIVE\" configuration option is set to an
appropriate integer as shown in the example below:

grep \"INACTIVE\" /etc/default/useradd
INACTIVE=35

If \"INACTIVE\" is not set to the value of \"35\" or less, this is a finding."
  tag "fix": "Configure the SLES for vRealize to disable account identifiers
after 35 days of inactivity after the password expiration. Run the following
command to change the configuration for useradd:

Replace [VALUE] in the command with any integer from the range 0<[VALUE]<= 35.
# sed -i \"s/^.*\\bINACTIVE\\b.*$/INACTIVE=[VALUE]/\" /etc/default/useradd

DoD recommendation is \"35\" days, but a lower value is acceptable. The value
\"-1\" will disable this feature and \"0\" will disable the account immediately
after the password expires."

describe parse_config_file('/etc/default/useradd') do
  its('INACTIVE') { should cmp 35 }
end

end

