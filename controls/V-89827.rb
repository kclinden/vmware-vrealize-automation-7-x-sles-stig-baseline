control "V-89827" do
  title "The SLES for vRealize must generate audit records when
successful/unsuccessful attempts to modify security objects occur."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000463-GPOS-00207"
  tag "gid": "V-89827"
  tag "rid": "SV-100477r1_rule"
  tag "stig_id": "VRAU-SL-001380"
  tag "fix_id": "F-96569r1_fix"
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
  tag "check": "To verify that auditing is configured for system administrator
actions, run the following command:

# auditctl -l | grep \"watch=/etc/sudoers\"

The result should return a rule for sudoers, such as:

LIST_RULES: exit,always watch=/etc/sudoers perm=wa key=sudoers

If there is no output, this is a finding."
  tag "fix": "At a minimum, the audit system should collect administrator
actions for all users and \"root\". Add the following to
\"/etc/audit/audit.rules\":

-w /etc/sudoers -p wa -k sudoers

OR

# /etc/dodscript.sh"
end

