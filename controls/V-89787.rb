control "V-89787" do
  title "The SLES for vRealize must provide an immediate real-time alert to the
SA and ISSO, at a minimum, of all audit failure events requiring real-time
alerts."
  desc  "It is critical for the appropriate personnel to be aware if a system
is at risk of failing to process audit logs as required. Without a real-time
alert, security personnel may be unaware of an impending failure of the audit
capability and system operation may be adversely affected.

    Alerts provide organizations with urgent messages. Real-time alerts provide
these messages immediately (i.e., the time from event detection to alert occurs
in seconds or less).
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000344-GPOS-00135"
  tag "gid": "V-89787"
  tag "rid": "SV-100437r1_rule"
  tag "stig_id": "VRAU-SL-001070"
  tag "fix_id": "F-96529r1_fix"
  tag "cci": ["CCI-001858"]
  tag "nist": ["AU-5 (2)", "Rev_4"]
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
  tag "check": "Check \"/etc/audit/auditd.conf\" for the \"space_left_action\"
with the following command:

# cat /etc/audit/auditd.conf | grep space_left_action

If the \"space_left_action\" parameter is missing, set to \"ignore\", set to
\"suspend\", set to \"single\", set to \"halt\", or is blank, this is a finding.

Expected Result:
space_left_action = SYSLOG

NOTES:
If the \"space_left_action\" is set to \"exec\" the system executes a
designated script. If this script informs the SA of the event, this is not a
finding.

If the \"space_left_action\" is set to \"email\" and the \"action_mail_acct\"
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

