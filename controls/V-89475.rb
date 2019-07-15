control "V-89475" do
  title "The SLES for vRealize must limit the number of concurrent sessions to
10 for all accounts and/or account types."
  desc  "Operating system management includes the ability to control the number
of users and user sessions that utilize an operating system. Limiting the
number of allowed users and sessions per user is helpful in reducing the risks
related to DoS attacks.

    This requirement addresses concurrent sessions for information system
accounts and does not address concurrent sessions by single users via multiple
system accounts. The maximum number of concurrent sessions should be defined
based upon mission needs and the operational environment for each system.
  "
  impact 0.3
  tag "severity": nil
  tag "gtitle": "SRG-OS-000027-GPOS-00008"
  tag "gid": "V-89475"
  tag "rid": "SV-100125r1_rule"
  tag "stig_id": "VRAU-SL-000040"
  tag "fix_id": "F-96217r2_fix"
  tag "cci": ["CCI-000054"]
  tag "nist": ["AC-10", "Rev_4"]
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
  tag "check": "Verify the SLES for vRealize limits the number of concurrent
sessions to \"10\" for all accounts and/or account types with the following
command:

# grep maxlogins /etc/security/limits.conf  | grep -v '#'

The default maxlimits should be set to a max of \"10\" or a documented site
defined number:

*              hard    maxlogins      10

If no such line exists, this is a finding."
  tag "fix": "Configure the SLES for vRealize to limit the number of concurrent
sessions to \"10\" for all accounts and/or account types by using the following
command.

sed -i 's/\\(^* *hard *maxlogins\\).*/*              hard    maxlogins
10/g' /etc/security/limits.conf"

  describe limits_conf('/etc/security/limits.conf') do
    its('*') { should include ['hard', 'maxlogins', '10'] }
  end

end

