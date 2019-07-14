control "V-89663" do
  title "The SMTP service HELP command must not be enabled."
  desc  "The HELP command should be disabled to mask version information. The
version of the SMTP service software could be used by attackers to target
vulnerabilities present in specific software versions."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89663"
  tag "rid": "SV-100313r1_rule"
  tag "stig_id": "VRAU-SL-000610"
  tag "fix_id": "F-96405r1_fix"
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
  tag "check": "Check the permissions of the sendmail helpfile:

ls -al /usr/lib/sendmail.d/helpfile

If the permissions are not \"0000\", this is a finding."
  tag "fix": "Run the following command to disable the sendmail helpfile:

# chmod 0000 /usr/lib/sendmail.d/helpfile"
end

