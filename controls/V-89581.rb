control "V-89581" do
  title "SLES for vRealize must enforce a 60-day maximum password lifetime
restriction."
  desc  "Any password, no matter how complex, can eventually be cracked.
Therefore, passwords need to be changed periodically. If the operating system
does not limit the lifetime of passwords and force users to change their
passwords, there is the risk that the operating system passwords could be
compromised."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000076-GPOS-00044"
  tag "gid": "V-89581"
  tag "rid": "SV-100231r1_rule"
  tag "stig_id": "VRAU-SL-000390"
  tag "fix_id": "F-96323r1_fix"
  tag "cci": ["CCI-000199"]
  tag "nist": ["IA-5 (1) (d)", "Rev_4"]
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
  tag "check": "To check that the SLES for vRealize enforces a 60-days or less
maximum password age, run the following command:

# grep PASS_MAX_DAYS /etc/login.defs | grep -v \"#\"

The DoD requirement is \"60\" days or less (greater than zero, as zero days
will lock the account immediately).

If \"PASS_MAX_DAYS\" is not set to the required value, this is a finding."
  tag "fix": "To configure the SLES for vRealize to enforce a 60-day or less
maximum password age, edit the file \"/etc/login.defs\" and add or correct the
following line. Replace [DAYS] with the appropriate amount of days.

# sed -i \"/^[^#]*PASS_MAX_DAYS/ c\\PASS_MAX_DAYS 60\" /etc/login.defs

The DoD requirement is \"60\" days or less (greater than zero, as zero days
will lock the account immediately)."

describe login_defs do
  its('PASS_MAX_DAYS') { should cmp 60 }
end

end

