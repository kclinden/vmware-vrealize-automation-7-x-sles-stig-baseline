control "V-89587" do
  title "The SLES for vRealize must prohibit password reuse for a minimum of
five generations - old passwords are being stored."
  desc  "Password complexity, or strength, is a measure of the effectiveness of
a password in resisting attempts at guessing and brute-force attacks. If the
information system or application allows the user to consecutively reuse their
password when that password has exceeded its defined lifetime, the end result
is a password that is not changed as per policy requirements."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000077-GPOS-00045"
  tag "gid": "V-89587"
  tag "rid": "SV-100237r1_rule"
  tag "stig_id": "VRAU-SL-000405"
  tag "fix_id": "F-96329r2_fix"
  tag "cci": ["CCI-000200"]
  tag "nist": ["IA-5 (1) (e)", "Rev_4"]
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
  tag "check": "Verify that the old password file \"opasswd\" exists, by
running the following command:

# ls /etc/security/opasswd

If \"/etc/security/opasswd\" does not exist, this is a finding."
  tag "fix": "Create the password history file.

# touch /etc/security/opasswd
# chown root:root /etc/security/opasswd
# chmod 0600 /etc/security/opasswd"
end

