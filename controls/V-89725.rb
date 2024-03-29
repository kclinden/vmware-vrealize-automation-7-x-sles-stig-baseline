control "V-89725" do
  title "The /var/log directory must have mode 0750 or less permissive."
  desc  "Only authorized personnel should be aware of errors and the details of
the errors. Error messages are an indicator of an organization's operational
state or can identify the operating system or platform. Additionally,
Personally Identifiable Information (PII) and operational information must not
be revealed through error messages to unauthorized personnel or their
designated representatives.

    The structure and content of error messages must be carefully considered by
the organization and development team. The extent to which the information
system is able to identify and handle error conditions is guided by
organizational policy and operational requirements.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000206-GPOS-00084"
  tag "gid": "V-89725"
  tag "rid": "SV-100375r1_rule"
  tag "stig_id": "VRAU-SL-000830"
  tag "fix_id": "F-96467r1_fix"
  tag "cci": ["CCI-001314"]
  tag "nist": ["SI-11 b", "Rev_4"]
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
  tag "check": "Verify that the /var/log directory has mode 0750 or less by
running the following command:

# ls -lad /var/log | cut -d' ' -f1

The output must look like the following example:

ls -lad /var/log | cut -d' ' -f1
drwxr-x---

If \"drwxr-x---\" is not returned as a result, this is a finding."
  tag "fix": "Change the permissions of the directory /var/log to \"0750\" by
running the following command:

# chmod 0750 /var/log"

#https://www.inspec.io/docs/reference/resources/file/
describe file('/var/log') do
  it { should_not be_more_permissive_than('0750') }
end

end

