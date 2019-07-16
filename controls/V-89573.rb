control "V-89573" do
  title "The SLES for vRealize must store only encrypted representations of
passwords."
  desc  "Passwords need to be protected at all times, and encryption is the
standard method for protecting passwords. If passwords are not encrypted, they
can be plainly read (i.e., clear text) and easily compromised."
  impact 0.7
  tag "severity": nil
  tag "gtitle": "SRG-OS-000073-GPOS-00041"
  tag "gid": "V-89573"
  tag "rid": "SV-100223r1_rule"
  tag "stig_id": "VRAU-SL-000365"
  tag "fix_id": "F-96315r1_fix"
  tag "cci": ["CCI-000196"]
  tag "nist": ["IA-5 (1) (c)", "Rev_4"]
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
  tag "check": "Check that the user account passwords are stored hashed using
sha512 by running the following command:

# more /etc/shadow

If the password hash does not begins with \"$6$\" for user accounts such as
\"root\" or \"admin\", this is a finding."
  tag "fix": "Reset the user password using the following command:

# passwd [user account]"

#Need to rework this. It currently will fail since several accounts have * or !
#describe shadow do
#  its('passwords'){ should cmp '$6$' }
#end

end

