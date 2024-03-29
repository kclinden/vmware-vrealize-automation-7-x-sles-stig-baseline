control "V-89479" do
  title "The SLES for vRealize must initiate a session lock after a 15-minute
period of inactivity for an SSH connection."
  desc  "A session time-out lock is a temporary action taken when a user stops
work and moves away from the immediate physical vicinity of the information
system but does not log out because of the temporary nature of the absence.
Rather than relying on the user to manually lock their operating system session
prior to vacating the vicinity, operating systems need to be able to identify
when a user's session has idled and take action to initiate the session lock.

    The session lock is implemented at the point where session activity can be
determined and/or controlled.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000029-GPOS-00010"
  tag "gid": "V-89479"
  tag "rid": "SV-100129r1_rule"
  tag "stig_id": "VRAU-SL-000055"
  tag "fix_id": "F-96221r1_fix"
  tag "cci": ["CCI-000057"]
  tag "nist": ["AC-11 a", "Rev_4"]
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
  tag "check": "Verify the SLES for vRealize initiates a session lock after a
15-minute period of inactivity for SSH.

Execute the following command:

# grep ClientAliveInterval /etc/ssh/sshd_config; grep  ClientAliveCountMax
/etc/ssh/sshd_config

Verify the following result:

ClientAliveInterval 900
ClientAliveCountMax 0

If this is not set, this is a finding."
  tag "fix": "Configure the SLES for vRealize to initiate a session lock after
a 15-minute period of inactivity for SSH.

Set the session lock after a 15-minute period by executing the following
command:

# sed -i 's/^.*\\bClientAliveInterval\\b.*$/ClientAliveInterval 900/'
/etc/ssh/sshd_config; sed -i
's/^.*\\bClientAliveCountMax\\b.*$/ClientAliveCountMax 0/' /etc/ssh/sshd_config"

describe sshd_config do
  its('ClientAliveInterval') { should cmp 900 }
  its('ClientAliveCountMax') { should cmp 0 }
end

end

