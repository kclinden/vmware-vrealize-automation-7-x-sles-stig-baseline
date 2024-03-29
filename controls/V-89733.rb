control "V-89733" do
  title "The SLES for vRealize must reveal error messages only to authorized
users."
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
  tag "gid": "V-89733"
  tag "rid": "SV-100383r1_rule"
  tag "stig_id": "VRAU-SL-000850"
  tag "fix_id": "F-96475r1_fix"
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
  tag "check": "Check the permissions of the syslog configuration file(s):

# ls -lL /etc/syslog-ng/syslog-ng.conf

If the mode of the file is more permissive than \"0640\", this is a finding."
  tag "fix": "Change the permissions of the syslog configuration file(s):

# chmod 640 /etc/syslog-ng/syslog-ng.conf"

#https://www.inspec.io/docs/reference/resources/file/
describe file('/etc/rsyslog.conf') do
  it { should_not be_more_permissive_than('0640') } #is this stig bad? Says to check syslog-ng.conf, but then says to fix rsyslog.conf
end


end

