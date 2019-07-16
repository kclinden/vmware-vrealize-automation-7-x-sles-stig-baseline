control "V-89477" do
  title "The SLES for vRealize must initiate a session lock after a 15-minute
period of inactivity for all connection types."
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
  tag "gid": "V-89477"
  tag "rid": "SV-100127r1_rule"
  tag "stig_id": "VRAU-SL-000050"
  tag "fix_id": "F-96219r1_fix"
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
  tag "check": "Check for the existence of the /etc/profile.d/tmout.sh file:

# ls -al /etc/profile.d/tmout.sh

Check for the presence of the TMOUT variable:

# grep TMOUT /etc/profile.d/tmout.sh

The value of TMOUT should be set to \"900\" seconds (15 minutes).

If the file does not exist, or the TMOUT variable is not set, this is a
finding."
  tag "fix": "Ensure the file exists and is owned by \"root\". If the file does
not exist, use the following commands to create the file:

# touch /etc/profile.d/tmout.sh
# chown root:root /etc/profile.d/tmout.sh
# chmod 644 /etc/profile.d/tmout.sh

Edit the file \"/etc/profile.d/tmout.sh\" and add the following lines:

TMOUT=900
readonly TMOUT
export TMOUT
mesg n 2>/dev/null"

  describe file('/etc/profile.d/tmout.sh') do
    it { should exist }
    its('content') { should match %r{TMOUT=900} }
  end

end

