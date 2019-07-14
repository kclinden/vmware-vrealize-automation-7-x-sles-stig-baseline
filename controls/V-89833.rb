control "V-89833" do
  title "The SLES for vRealize must generate audit records when
successful/unsuccessful logon attempts occur."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000470-GPOS-00214"
  tag "gid": "V-89833"
  tag "rid": "SV-100483r1_rule"
  tag "stig_id": "VRAU-SL-001405"
  tag "fix_id": "F-96575r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
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
  tag "check": "The message types that are always recorded to
/var/log/audit/audit.log include \"LOGIN\", \"USER_LOGIN\", \"USER_START\",
\"USER_END\" among others and do not need to be added to audit.rules.

The log files /var/log/faillog, /var/log/lastlog, and /var/log/tallylog must be
protected from tampering of the logon records:

# egrep \"faillog|lastlog|tallylog\" /etc/audit/audit.rules

If /var/log/faillog, /var/log/lastlog, and /var/log/tallylog entries do not
exist, this is a finding."
  tag "fix": "Ensure the auditing of logons by modifying /etc/audit/audit.rules
to contain:

-w /var/log/faillog -p wa
-w /var/log/lastlog -p wa
-w /var/log/tallylog -p wa

OR

# /etc/dodscript.sh"
end

