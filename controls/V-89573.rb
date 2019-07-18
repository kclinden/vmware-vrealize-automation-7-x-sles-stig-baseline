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

bad_users = inspec.shadow.where { password =~ /[^!*]/ && password !~ /\$6\$/ }.users

describe 'Password hashes in /etc/shadow' do
  it 'should only contain SHA512 hashes' do
    failure_message = "Users without SHA512 hashes: #{bad_users.join(', ')}"
    expect(bad_users).to be_empty, failure_message
  end
end


end

