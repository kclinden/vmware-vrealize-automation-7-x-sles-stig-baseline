control "V-89785" do
  title "The SLES for vRealize must immediately notify the SA and ISSO (at a
minimum) when allocated audit record storage volume reaches 75% of the
repository maximum audit record storage capacity."
  desc  "If security personnel are not notified immediately when storage volume
reaches 75% utilization, they are unable to plan for audit record storage
capacity expansion."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000343-GPOS-00134"
  tag "gid": "V-89785"
  tag "rid": "SV-100435r1_rule"
  tag "stig_id": "VRAU-SL-001065"
  tag "fix_id": "F-96527r1_fix"
  tag "cci": ["CCI-001855"]
  tag "nist": ["AU-5 (1)", "Rev_4"]
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
  tag "check": "Check \"/etc/audit/auditd.conf\" for the\" space_left_action\"
with the following command:

# cat /etc/audit/auditd.conf | grep space_left_action

If the \"space_left_action\" parameter is missing, set to \"ignore\", set to
\"suspend\", set to \"single\", set to \"halt\", or is blank, this is a finding.

Expected Result:
space_left_action = SYSLOG

NOTES:
If the space_left_action is set to \"exec\" the system executes a designated
script. If this script informs the SA of the event, this is not a finding.

If the space_left_action is set to \"email\" and the \"action_mail_acct\"
parameter is not set to the email address of the system administrator, this is
a finding.

The \"action_mail_acct parameter\", if missing, defaults to \"root\". Note that
if the email address of the system administrator is on a remote system
\"sendmail\" must be available."
  tag "fix": "Set the \"space_left_action\" parameter to the valid setting
\"SYSLOG\",  by running the following command:

# sed -i \"/^[^#]*space_left_action/ c\\admin_space_left_action = SYSLOG\"
/etc/audit/auditd.conf

Restart the audit service:

# service auditd restart"
end

