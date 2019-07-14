control "V-89653" do
  title "Files executed through a mail aliases file must have mode 0755 or less
permissive."
  desc  "If a file executed through a mail alias file has permissions greater
than 0755, it can be modified by an unauthorized user and may contain malicious
code or instructions that could compromise the system."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89653"
  tag "rid": "SV-100303r1_rule"
  tag "stig_id": "VRAU-SL-000585"
  tag "fix_id": "F-96395r1_fix"
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
  tag "check": "Examine the contents of the /etc/aliases file:

# more /etc/aliases

Examine the aliases file for any directories or paths that may be used:

# ls -lL <file referenced from aliases>

Check the permissions for any paths referenced.

If any file referenced from the aliases file has a mode more permissive than
\"0755\", this is a finding."
  tag "fix": "Use the \"chmod\" command to change the access permissions for
files executed from the alias file:

# chmod 0755 <file referenced from aliases>"
end

